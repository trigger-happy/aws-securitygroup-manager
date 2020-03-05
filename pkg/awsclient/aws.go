package awsclient

import (
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// A bundle of other structs to serve as a context for this connection.
type AwsContext struct {
	session         *session.Session
	ec2             *ec2.EC2
	SecurityGroupID string
	OwnerID         string
}

// This is the equivalent of a firewall inbound rule entry in the AWS security group.
type RuleEntry struct {
	NodeName string
	OwnerID  string
	FromPort int64
	ToPort   int64
	IP       string
	Protocol string
}

func (r RuleEntry) String() string {
	return fmt.Sprintf("RuleEntry{NodeName: %s, OwnerID: %s, IP: %s, Protocol: %s, FromPort: %d, ToPort: %d}",
		r.NodeName, r.OwnerID, r.IP, r.Protocol, r.FromPort, r.ToPort)
}

// Initialize the connection to the AWS API.
func (a *AwsContext) Init() error {
	err := checkEnvVars()
	if err != nil {
		return fmt.Errorf("Init fail: %w", err)
	}

	a.session, err = session.NewSession(&aws.Config{})
	if err != nil {
		return fmt.Errorf("Error initializing AWS Session: %w", err)
	}

	a.ec2 = ec2.New(a.session)
	a.SetOwnerIDFromEnv()
	a.SetSecurityGroupIDFromEnv()

	return nil
}

// Given the SecurityGroupID in the current context, get the list of firewall
// entries that are tagged under the current OwnerID.
func (a *AwsContext) GetOwnedEntries() ([]*RuleEntry, error) {
	permissions, err := a.GetInboundRulesOwnedByID()
	if err != nil {
		return nil, fmt.Errorf("GetOwnedEntries error: %w", err)
	}

	result := make([]*RuleEntry, 0)
	for _, iprange := range permissions[0].IpRanges {
		rule := RuleEntryFromDescription(iprange.Description)
		rule.FromPort = *permissions[0].FromPort
		rule.ToPort = *permissions[0].ToPort
		rule.Protocol = *permissions[0].IpProtocol
		rule.IP = *iprange.CidrIp
		result = append(result, rule)
	}

	return result, nil
}

// Delete all the firewall entries tagged under the current OwnerID and then
// add a fresh set of rules according to the entries parameter.
func (a *AwsContext) ReplaceOwnedEntries(entries []*RuleEntry) error {
	// Convert from RuleEntry to ec2.IpPermission objects
	ruleList := make([]*ec2.IpPermission, 0)
	for _, entry := range entries {
		var iprange ec2.IpRange
		description := entry.GetDescription()
		iprange.CidrIp = &entry.IP
		iprange.Description = &description

		var replacement ec2.IpPermission
		replacement.FromPort = &entry.FromPort
		replacement.ToPort = &entry.ToPort
		replacement.IpProtocol = &entry.Protocol
		replacement.IpRanges = append(replacement.IpRanges, &iprange)

		ruleList = append(ruleList, &replacement)
	}

	// get all the rules in this security group
	oldRules, err := a.GetInboundRules()
	if err != nil {
		return fmt.Errorf("ReplaceOwnedEntries error while getting old rules: %w", err)
	}

	// expand the rules and then get the ones that we don't own
	expandedRules := expandRules(oldRules)
	notMyRules := filterInboundRules(expandedRules, &a.OwnerID, false)
	a.DeleteInboundRules(oldRules)

	// create the new rules list
	newRules := make([]*ec2.IpPermission, 0)
	newRules = append(newRules, notMyRules...)
	newRules = append(newRules, ruleList...)

	// save it
	return a.SetInboundRules(newRules)
}

// The Description column in an AWS Security Group allows for arbitrary data.
// We use that here to tag entries for ownership. Anything that is "owned" by
// the current context is fair game while everything else is left alone.
const descriptionFormat = "ownerid=%s ; nodename=%s"

// Create a "Description" according to the OwnerID and NodeName values.
func (r *RuleEntry) GetDescription() string {
	return fmt.Sprintf(descriptionFormat, r.OwnerID, r.NodeName)
}

// Given the string found in the Description column of an inbound rule, get the
// OwnerID and NodeName out of it.
func ParseDescription(description *string) (*string, *string) {
	var ownerid, nodename string
	_, err := fmt.Sscanf(*description, descriptionFormat, &ownerid, &nodename)
	if err != nil {
		return nil, nil
	}

	return &ownerid, &nodename
}

// Create a RuleEntry from a Description string. Note that this will only fill up
// the OwnerID and NodeName fields so the rest will still have to be filled up
// after.
func RuleEntryFromDescription(description *string) *RuleEntry {
	var result RuleEntry
	_, err := fmt.Sscanf(*description, descriptionFormat, &result.OwnerID, &result.NodeName)
	if err != nil {
		return nil
	}

	return &result
}

// Convert a list of RuleEntry objects into a list ofec2.IpPermission objects.
func RuleEntriesToAwsIpPermissions(entries []*RuleEntry) []*ec2.IpPermission {
	permissions := make([]*ec2.IpPermission, 0)

	for _, entry := range entries {
		ipranges := make([]*ec2.IpRange, 0)
		var ipr ec2.IpRange
		ipr.SetCidrIp(entry.IP)
		ipr.SetDescription(entry.GetDescription())
		ipranges = append(ipranges, &ipr)

		var tmpPerm ec2.IpPermission
		tmpPerm.SetFromPort(entry.FromPort)
		tmpPerm.SetToPort(entry.ToPort)
		tmpPerm.SetIpProtocol(entry.Protocol)
		tmpPerm.SetIpRanges(ipranges)

		permissions = append(permissions, &tmpPerm)
	}

	return permissions
}

// Set the OwnerID from the environment var
func (a *AwsContext) SetOwnerIDFromEnv() error {
	ownerID := os.Getenv("AWS_SGMANAGER_OWNER_ID")
	if ownerID == "" {
		return fmt.Errorf("Env var AWS_SGMANAGER_OWNER_ID not set")
	}

	a.OwnerID = ownerID
	return nil
}

// Set the SecurityGroupID from the environment var
func (a *AwsContext) SetSecurityGroupIDFromEnv() error {
	sgid := os.Getenv("AWS_SECURITY_GROUP_ID")
	if sgid == "" {
		return fmt.Errorf("Env var AWS_SECURITY_GROUP_ID not set")
	}

	a.SecurityGroupID = sgid
	return nil
}

// Check if the required list of environment variables have been set. Return
// an error if any of them are missing. Some of these will be read by the AWS
// Go SDK directly.
func checkEnvVars() error {
	envVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_DEFAULT_REGION",
		"AWS_VPC_ID",
		"AWS_SGMANAGER_OWNER_ID",
		"AWS_SECURITY_GROUP_ID",
	}

	for _, e := range envVars {
		if os.Getenv(e) == "" {
			errorMessage := fmt.Sprintf("Env var %s not set", e)
			return errors.New(errorMessage)
		}
	}

	return nil
}

// Get all the inbound rules that are part of the current Security Group.
func (a *AwsContext) GetInboundRules() ([]*ec2.IpPermission, error) {
	securityGroups, err := a.ec2.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{&a.SecurityGroupID},
	})

	if err != nil {
		return nil, fmt.Errorf("GetInboundRules error: %w", err)
	}

	var results []*ec2.IpPermission
	results = securityGroups.SecurityGroups[0].IpPermissions
	return results, nil
}

// Get the inbound rules that are under the current Security Group and tagged
// as owned by OwnerID.
func (a *AwsContext) GetInboundRulesOwnedByID() ([]*ec2.IpPermission, error) {
	originalSet, err := a.GetInboundRules()
	if err != nil {
		return nil, fmt.Errorf("GetInboundRulesOwnedByID error: %w", err)
	}

	results := filterInboundRules(originalSet, &a.OwnerID, true)
	return results, nil
}

// Get the inbound rules that are under the current Security Group and are not
// tagged as owned by OwnerID.
func (a *AwsContext) GetInboundRulesNotOwnedByID() ([]*ec2.IpPermission, error) {
	originalSet, err := a.GetInboundRules()
	if err != nil {
		return nil, fmt.Errorf("GetInboundRulesOwnedByID error: %w", err)
	}

	results := filterInboundRules(originalSet, &a.OwnerID, false)
	return results, nil
}

func isRuleOwnedByID(rule *ec2.IpPermission, ownerID *string) bool {
	owner, _ := ParseDescription(rule.IpRanges[0].Description)
	if owner == nil {
		return false
	}

	return *owner == *ownerID
}

// AWS tends to lump up several IpPermission objects together if their protocol
// and port ranges match and then put the differences into an ipRanges array.
// This function will create new ec2.IpPermission objects for each of those
// IpRange entries.
func expandRules(rules []*ec2.IpPermission) []*ec2.IpPermission {
	results := make([]*ec2.IpPermission, 0)

	for _, rule := range rules {
		for _, iprange := range rule.IpRanges {
			var newRule ec2.IpPermission
			newRule.FromPort = rule.FromPort
			newRule.ToPort = rule.ToPort
			newRule.IpProtocol = rule.IpProtocol
			newRule.IpRanges = make([]*ec2.IpRange, 0)
			newRule.IpRanges = append(newRule.IpRanges, iprange)
			results = append(results, &newRule)
		}
	}

	return results
}

// Given a list of ec2.IpPermission objects, return the ones that are owned by
// ownerID if returnOwned is true. Do the opposite otherwise.
func filterInboundRules(rules []*ec2.IpPermission, ownerID *string, returnOwned bool) []*ec2.IpPermission {
	results := make([]*ec2.IpPermission, 0)

	expandedRules := expandRules(rules)
	for _, rule := range expandedRules {
		ruleIsOwned := isRuleOwnedByID(rule, ownerID)
		if (returnOwned && ruleIsOwned) ||
			(!returnOwned && !ruleIsOwned) {
			results = append(results, rule)
		}
	}

	return results
}

func (a *AwsContext) SetInboundRules(rules []*ec2.IpPermission) error {
	var ingressInput ec2.AuthorizeSecurityGroupIngressInput
	ingressInput.SetIpPermissions(rules)
	ingressInput.SetGroupId(a.SecurityGroupID)

	_, err := a.ec2.AuthorizeSecurityGroupIngress(&ingressInput)
	if err != nil {
		return fmt.Errorf("Error setting inbound rules: %w", err)
	}

	return nil
}

func (a *AwsContext) DeleteInboundRules(rules []*ec2.IpPermission) error {
	if len(rules) == 0 {
		return nil
	}

	var ingressInput ec2.RevokeSecurityGroupIngressInput
	ingressInput.SetIpPermissions(rules)
	ingressInput.SetGroupId(a.SecurityGroupID)

	_, err := a.ec2.RevokeSecurityGroupIngress(&ingressInput)
	if err != nil {
		return fmt.Errorf("Error deleting inbound rules: %w", err)
	}

	return nil
}

func (a *AwsContext) DeleteRuleEntries(entries []*RuleEntry) error {
	if len(entries) == 0 {
		return nil
	}

	permissions := RuleEntriesToAwsIpPermissions(entries)
	if permissions == nil {
		return fmt.Errorf("Error converting RuleEntry structs to ec2.IpPermission structs")
	}

	return a.DeleteInboundRules(permissions)
}
