package parser

import gotreesitter "github.com/odvcencio/gotreesitter"

func NodeText(n *gotreesitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	return n.Text(source)
}
