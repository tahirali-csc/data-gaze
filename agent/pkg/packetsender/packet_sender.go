package packetsender

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"agent/pkg/model"

	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
}

func sendPacketInChunksWithRetry(url string, packet model.Packet, chunkSize, maxRetries int) error {
	client := &http.Client{}

	packetData, err := json.Marshal(packet)
	if err != nil {
		return fmt.Errorf("error marshalling packet: %v", err)
	}

	// Create a new retryable HTTP client
	client := retryablehttp.NewClient()

	// Optionally, you can customize the retryable HTTP client
	client.RetryMax = 3 // Set the maximum number of retries

	// Create a new request
	req, err := retryablehttp.NewRequest(http.MethodPost, "https://localhost:8080/connections/", nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error performing request: %v", err)
	}
	defer resp.Body.Close()

	// Process the response
	if resp.StatusCode == http.StatusCreated {
		fmt.Println("POST request succeeded!")
	} else {
		fmt.Printf("POST request failed with status code: %d\n", resp.StatusCode)
	}

}
