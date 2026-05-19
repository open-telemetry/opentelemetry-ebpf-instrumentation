// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
)

func main() {
	client := openai.NewClient()

	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("How do I check if a slice is empty in Go?"),
		},
		Model: openai.ChatModelGPT4o,
	}

	completion, err := client.Chat.Completions.New(context.Background(), params)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Reference fields so the symbols are retained in the binary
	// for the offsets tracker to inspect.
	var c openai.ChatCompletion = *completion
	fmt.Println(c.ID)
	fmt.Println(c.Model)
	fmt.Println(c.Created)
	fmt.Println(len(c.Choices))

	if len(c.Choices) > 0 {
		choice := c.Choices[0]
		fmt.Println(choice.Message.Content)
	}

	var u openai.CompletionUsage = c.Usage
	fmt.Println(u.CompletionTokens)
	fmt.Println(u.PromptTokens)
	fmt.Println(u.TotalTokens)
}
