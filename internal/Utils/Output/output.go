package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
)

func WriteToFile(data map[string]interface{}, format string, filename string) error {
	var content []byte
	var err error

	switch format {
	case "json":
		content, err = json.MarshalIndent(data, "", "  ")
	case "xml":
		content, err = xml.MarshalIndent(data, "", "  ")
	case "normal":
		content = []byte(PrintToString(data))
	default:
		return fmt.Errorf("invalid format: %s", format)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0644)
}

func PrintToConsole(data map[string]interface{}, format string) {
	if format == "normal" {
		fmt.Println(PrintToString(data))
		return
	}

	var output []byte
	var err error

	if format == "json" {
		output, err = json.MarshalIndent(data, "", "  ")
	} else if format == "xml" {
		output, err = xml.MarshalIndent(data, "", "  ")
	} else {
		fmt.Println("[-] Invalid output format")
		return
	}

	if err != nil {
		fmt.Println("[-] Error formatting output:", err)
		return
	}

	fmt.Println(string(output))
}

func PrintToString(data map[string]interface{}) string {
	output := "=== ReconNio Report ===\n"
	for key, val := range data {
		output += fmt.Sprintf("\n[%s]\n%v\n", key, val)
	}
	return output
}
