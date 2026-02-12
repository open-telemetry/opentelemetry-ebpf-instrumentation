package meta

import (
	"context"
	"io"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func awsNodeFetcher(ctx context.Context) ([]Entry, error) {
	log := slog.With("component", "meta.NodeStore.awsNodeFetcher")

	// Create IMDS client with default options
	// The client will use IMDSv2 by default with a 5-second timeout
	client := imds.New(imds.Options{})

	// Helper function to get metadata from a path
	getMetadata := func(path string) (string, error) {
		output, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
			Path: path,
		})
		if err != nil {
			return "", err
		}
		defer output.Content.Close()

		data, err := io.ReadAll(output.Content)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	// Try to get instance ID first to check if we're on AWS EC2
	// If this fails, we're likely not on AWS, so return empty without error
	// (no point in retrying if IMDS is not available)
	instanceID, err := getMetadata("instance-id")
	if err != nil {
		// Not on AWS EC2 - return empty slice without error
		// This prevents unnecessary retries when running on baremetal, GCP, etc.
		log.Debug("not on AWS EC2", "error", err)
		return nil, nil
	}

	// Collect all available host metadata attributes
	// Following OpenTelemetry semantic conventions for host resources:
	// https://opentelemetry.io/docs/specs/semconv/resource/host/
	var entries []Entry

	// host.id - unique host identifier (instance ID in AWS)
	entries = append(entries, Entry{Key: attr.HostID, Value: instanceID})

	// host.type - machine type (e.g., t3.micro, m5.large)
	if instanceType, err := getMetadata("instance-type"); err == nil {
		entries = append(entries, Entry{Key: attr.HostType, Value: instanceType})
	} else {
		log.Debug("failed to get instance type", "error", err)
	}

	// host.name - hostname
	if hostname, err := getMetadata("hostname"); err == nil {
		entries = append(entries, Entry{Key: attr.HostName, Value: hostname})
	} else {
		log.Debug("failed to get hostname", "error", err)
	}

	//TODO
	//attr.HostImageID
	//attr.HostImageName
	//attr.HostImageVersion

	return entries, nil
}
