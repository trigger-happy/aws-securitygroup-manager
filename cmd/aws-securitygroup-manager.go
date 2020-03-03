package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/trigger-happy/aws-securitygroup-manager/pkg/awsclient"
	"github.com/trigger-happy/aws-securitygroup-manager/pkg/k8sclient"
)

// Delay between runs of the main business logic.
const sleepTimeSeconds = 60

// Additional parameters for firewall entries
// There are more, but they're declared in the awsclient package
type EntryParams struct {
	OwnerID  string
	FromPort int64
	ToPort   int64
	IP       string
	Protocol string
}

// Load the env vars into an EntryParams object.
func getEntryParams() (*EntryParams, error) {
	var params EntryParams
	var err error

	envVars := []string{
		"AWS_SGMANAGER_OWNER_ID",
		"FROM_PORT",
		"TO_PORT",
		"PROTOCOL",
	}

	// verify first that the env vars we want are defined
	for _, e := range envVars {
		if os.Getenv(e) == "" {
			return nil, fmt.Errorf("Env var %s not set", e)
		}
	}

	params.OwnerID = os.Getenv("AWS_SGMANAGER_OWNER_ID")
	params.Protocol = os.Getenv("PROTOCOL")

	params.FromPort, err = strconv.ParseInt(os.Getenv("FROM_PORT"), 10, 64)
	bailOnError(err)

	params.ToPort, err = strconv.ParseInt(os.Getenv("TO_PORT"), 10, 64)
	bailOnError(err)

	return &params, nil
}

// Convert a node name and address pair into a firewall entry for the
// AWS security group.
func ruleEntriesFromAddressPairs(nap []*k8sclient.NameAddressPair, entryParams *EntryParams) []*awsclient.RuleEntry {
	results := make([]*awsclient.RuleEntry, 0)
	for _, addressPair := range nap {
		var ruleEntry awsclient.RuleEntry
		ruleEntry.NodeName = addressPair.Name
		ruleEntry.IP = addressPair.Address + "/32"
		ruleEntry.OwnerID = entryParams.OwnerID
		ruleEntry.Protocol = entryParams.Protocol
		ruleEntry.FromPort = entryParams.FromPort
		ruleEntry.ToPort = entryParams.ToPort
		results = append(results, &ruleEntry)
	}

	return results
}

func bailOnError(err error) {
	if err == nil {
		return
	}

	fmt.Printf("%s\n", err)
	os.Exit(1)
}

func main() {
	fmt.Println("Reading env vars")
	entryParams, err := getEntryParams()
	bailOnError(err)

	fmt.Println("Initializing kubernetes client")
	k8sClient, err := k8sclient.GetKubeClient()
	bailOnError(err)

	fmt.Println("Initializing AWS client")
	var aws awsclient.AwsContext
	err = aws.Init()
	bailOnError(err)

	for true {
		fmt.Println("Getting list of node names and addresses")
		addressList, err := k8sclient.GetIPAddressList(k8sClient)
		bailOnError(err)

		ruleEntries := ruleEntriesFromAddressPairs(addressList, entryParams)

		fmt.Println("Replacing rules in AWS owned by this instance")
		err = aws.ReplaceOwnedEntries(ruleEntries)
		bailOnError(err)

		fmt.Println("Done, going to sleep")

		time.Sleep(sleepTimeSeconds * time.Second)
	}
}
