// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// Only complete, known page titles/headings establish these causes. A script,
// a link label or a generic mention of confirmation is not a denial page.
func slackQRPageDenial(body []byte) slackQRReason {
	tokens := html.NewTokenizer(bytes.NewReader(body))
	var heading, ignored string
	var ignoredDepth int
	var text strings.Builder
	var tooLong bool
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			return qrReasonNone
		}
		switch kind {
		case html.StartTagToken, html.EndTagToken:
			name, hasAttr := tokens.TagName()
			tag := string(name)
			if ignored != "" {
				if tag == ignored {
					if kind == html.StartTagToken {
						ignoredDepth++
					} else {
						ignoredDepth--
						if ignoredDepth == 0 {
							ignored = ""
						}
					}
				}
				continue
			}
			if kind == html.StartTagToken {
				hidden := false
				for hasAttr {
					key, value, more := tokens.TagAttr()
					switch string(key) {
					case "hidden":
						hidden = true
					case "aria-hidden":
						hidden = hidden || strings.EqualFold(string(value), "true")
					case "style":
						style := strings.ToLower(strings.Join(strings.Fields(string(value)), ""))
						hidden = hidden || strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden")
					}
					hasAttr = more
				}
				if hidden {
					ignored, ignoredDepth = tag, 1
					continue
				}
				switch tag {
				case "script", "style", "template", "noscript", "textarea":
					ignored, ignoredDepth = tag, 1
				case "title", "h1", "h2":
					heading = tag
					text.Reset()
					tooLong = false
				}
			} else if heading != "" && tag == heading {
				if !tooLong {
					switch strings.ToLower(strings.Join(strings.Fields(text.String()), " ")) {
					case "link expired", "link expired | slack", "this link has expired", "this link has expired | slack":
						return qrLinkExpired
					case "sign in on your other device", "sign in on your other device | slack",
						"confirm this sign-in on your other device", "confirm this sign-in on your other device | slack":
						return qrDeviceConfirmationRequired
					}
				}
				heading = ""
			}
		case html.TextToken:
			if heading != "" && !tooLong {
				part := tokens.Text()
				if text.Len()+len(part) > 512 {
					tooLong = true
				} else {
					text.Write(part)
				}
			}
		}
	}
}
