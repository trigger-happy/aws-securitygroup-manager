package awsclient

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
)

func TestReplaceOwnedEntries(t *testing.T) {
	var aws AwsContext
	err := aws.Init()
	if err != nil {
		t.Fatalf("AwsContext object init fail: %s", err)
	}

	t.Run("Valid security group replacement", func(t *testing.T) {
		validEntries := []*RuleEntry{
			&RuleEntry{NodeName: "node1", OwnerID: aws.OwnerID, FromPort: 2345, ToPort: 5432, IP: "192.172.0.1/32", Protocol: "tcp"},
			&RuleEntry{NodeName: "node2", OwnerID: aws.OwnerID, FromPort: 2345, ToPort: 5432, IP: "192.172.0.2/32", Protocol: "tcp"},
			&RuleEntry{NodeName: "node3", OwnerID: aws.OwnerID, FromPort: 2345, ToPort: 5432, IP: "192.172.0.3/32", Protocol: "tcp"},
			&RuleEntry{NodeName: "node4", OwnerID: aws.OwnerID, FromPort: 2345, ToPort: 5432, IP: "192.172.0.4/32", Protocol: "tcp"},
			&RuleEntry{NodeName: "node5", OwnerID: aws.OwnerID, FromPort: 2345, ToPort: 5432, IP: "192.172.0.5/32", Protocol: "tcp"},
		}

		err = aws.ReplaceOwnedEntries(validEntries)
		if err != nil {
			t.Errorf("ReplaceOwnedEntries failure: %s", err)
		}

		ownedEntries, err := aws.GetOwnedEntries()
		if err != nil {
			t.Errorf("Could not get owned entries: %s", err)
		}
		if len(ownedEntries) != len(validEntries) {
			t.Errorf("Replacement of owned entries failed")
		}

		// cleanup by deleting the rules we added in
		err = aws.DeleteRuleEntries(validEntries)
		if err != nil {
			t.Fatalf("Could not cleanup inserted rules in security group!")
		}
	})

	t.Run("Invalid security group replacement", func(t *testing.T) {
		//TODO implement me
	})
}

func TestGetDescription(t *testing.T) {
	validRules := []RuleEntry{
		RuleEntry{NodeName: "aaa", OwnerID: "aaa"},
		RuleEntry{NodeName: "333", OwnerID: "333"},
		RuleEntry{NodeName: "a-3", OwnerID: "a-3"},
		RuleEntry{NodeName: "aaaaaaaaaaaaaaaaaa", OwnerID: "aaaaaaaaaaaaaaaaaa"},
	}

	expectedDescriptions := []string{
		"ownerid=aaa ; nodename=aaa",
		"ownerid=333 ; nodename=333",
		"ownerid=a-3 ; nodename=a-3",
		"ownerid=aaaaaaaaaaaaaaaaaa ; nodename=aaaaaaaaaaaaaaaaaa",
	}

	for idx, rule := range validRules {
		description := rule.GetDescription()
		if description != expectedDescriptions[idx] {
			t.Errorf("RuleEntry %s generated %s, should be %s", rule, description, expectedDescriptions[idx])
		}
	}

	//TODO tests here for invalid RuleEntry objects
}

func TestRuleEntryFromDescription(t *testing.T) {
	validDescriptions := []string{
		"ownerid=aaa ; nodename=aaa",
		"ownerid=333 ; nodename=333",
		"ownerid=a-3 ; nodename=a-3",
		"ownerid=aaaaaaaaaaaaaaaaaa ; nodename=aaaaaaaaaaaaaaaaaa",
	}

	expectedRuleEntries := []RuleEntry{
		RuleEntry{NodeName: "aaa", OwnerID: "aaa"},
		RuleEntry{NodeName: "333", OwnerID: "333"},
		RuleEntry{NodeName: "a-3", OwnerID: "a-3"},
		RuleEntry{NodeName: "aaaaaaaaaaaaaaaaaa", OwnerID: "aaaaaaaaaaaaaaaaaa"},
	}

	for idx, description := range validDescriptions {
		rule := RuleEntryFromDescription(&description)
		expectedRule := expectedRuleEntries[idx]
		if (rule == nil) || (expectedRule != *rule) {
			t.Errorf("Description '%s' generated rule %s, expected %s", description, rule, expectedRule)
		}
	}

	//TODO tests here for invalid descriptions
}

func TestGetInboundRules(t *testing.T) {
	var aws AwsContext
	err := aws.Init()

	if err != nil {
		t.Fatalf("AwsContext object init fail: %s", err)
	}

	// test with the env var provided security group
	t.Run("Security group from env var", func(t *testing.T) {
		_, err := aws.GetInboundRules()

		if err != nil {
			t.Errorf("AWS_SECURITY_GROUP_ID env var is invalid, continuing anyway")
		}
	})

	// testing with an invalid security group
	t.Run("Invalid security group", func(t *testing.T) {
		invalidID := "INVALID"
		aws.SecurityGroupID = invalidID
		_, err := aws.GetInboundRules()

		if err == nil {
			t.Errorf("Expected an error, but got none")
		}
	})
}

func TestSetInboundRules(t *testing.T) {
	var aws AwsContext
	err := aws.Init()

	if err != nil {
		t.Fatalf("AwsContext object init fail: %s", err)
	}

	t.Run("Valid security group, valid rules", func(t *testing.T) {
		ipRange := ec2.IpRange{}
		ipRange.SetCidrIp("192.168.1.1/32")
		ipRange.SetDescription("Testing rule")

		rule := ec2.IpPermission{}
		rule.SetFromPort(5432)
		rule.SetToPort(5432)
		rule.SetIpProtocol("tcp")
		rule.SetIpRanges([]*ec2.IpRange{&ipRange})

		err = aws.SetInboundRules([]*ec2.IpPermission{&rule})
		if err != nil {
			t.Errorf("Error setting inbound rules: %s", err)
		}

		// cleanup
		err = aws.DeleteInboundRules([]*ec2.IpPermission{&rule})
		if err != nil {
			t.Fatalf("Error cleaning up: %s", err)
		}
	})

	t.Run("Valid security group, invalid rules", func(t *testing.T) {
		var rules []*ec2.IpPermission

		err = aws.SetInboundRules(rules)

		if err == nil {
			t.Errorf("Expected an error while setting invalid rules but got none")
		}
	})

	t.Run("Invalid security group", func(t *testing.T) {
		var rules []*ec2.IpPermission

		securityGroupID := "INVALID"
		aws.SecurityGroupID = securityGroupID
		err = aws.SetInboundRules(rules)

		if err == nil {
			t.Errorf("Expected an error setting rules on an invalid security group but got none")
		}
	})
}

func TestGetInboundRulesOwnedByID(t *testing.T) {
	var aws AwsContext
	err := aws.Init()
	if err != nil {
		t.Fatalf("AwsContext object init fail: %s", err)
	}

	//TODO implement me
}

func TestGetInboundRulesNotOwnedByID(t *testing.T) {
	var aws AwsContext
	err := aws.Init()
	if err != nil {
		t.Fatalf("AwsContext object init fail: %s", err)
	}

	//TODO implement me
}
