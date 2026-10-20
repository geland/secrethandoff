// A fake browser used only by the grouped raw-transport leak regression.
// It receives dummy values through its process environment, never files.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	origin, token, ok := strings.Cut(os.Args[1], "/r#")
	if !ok {
		os.Exit(1)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", origin+"/api/request", nil)
	req.Header.Set("X-Secrethandoff-Token", token)
	res, err := client.Do(req)
	if err != nil {
		os.Exit(1)
	}
	var view struct{ Kind string }
	err = json.NewDecoder(res.Body).Decode(&view)
	res.Body.Close()
	if err != nil {
		os.Exit(1)
	}
	action, body := "approve", []byte("{}")
	if view.Kind == "fill" {
		var values map[string]string
		if json.Unmarshal([]byte(os.Getenv("SECRETHANDOFF_GROUP_DUMMY_VALUES")), &values) != nil {
			os.Exit(1)
		}
		body, _ = json.Marshal(map[string]any{"values": values})
		action = "fill"
	}
	req, _ = http.NewRequest("POST", origin+"/api/"+action, bytes.NewReader(body))
	req.Header.Set("X-Secrethandoff-Token", token)
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	res, err = client.Do(req)
	if err != nil {
		os.Exit(1)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		os.Exit(1)
	}
}
