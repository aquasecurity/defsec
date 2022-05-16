package scan

import (
	"bytes"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
)

func highlight(filename string, input []byte, theme string) []byte {

	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Fallback
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get(theme)
	if style == nil {
		style = styles.Fallback
	}
	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

	// replace windows line endings
	input = bytes.ReplaceAll(input, []byte{0x0d}, []byte{})
	iterator, err := lexer.Tokenise(nil, string(input))
	if err != nil {
		return input
	}

	buffer := bytes.NewBuffer([]byte{})
	if err := formatter.Format(buffer, style, iterator); err != nil {
		return input
	}

	return shiftANSIOverLineEndings(buffer.Bytes())
}

func shiftANSIOverLineEndings(input []byte) []byte {
	var output []byte
	prev := byte(0)
	inCSI := false
	csiShouldCarry := false
	var csi []byte
	var skipOutput bool
	for _, r := range input {
		skipOutput = false
		if !inCSI {
			switch {
			case r == '\n':
				if csiShouldCarry && len(csi) > 0 {
					skipOutput = true
					output = append(output, '\n')
					output = append(output, csi...)
					csi = nil
					csiShouldCarry = false
				}
			case r == '[' && prev == 0x1b:
				inCSI = true
				csi = append(csi, 0x1b, '[')
				output = output[:len(output)-1]
				skipOutput = true
			default:
				csiShouldCarry = false
				if len(csi) > 0 {
					output = append(output, csi...)
					csi = nil
				}
			}
		} else {
			csi = append(csi, r)
			skipOutput = true
			switch {
			case r >= 0x40 && r <= 0x7E:
				csiShouldCarry = true
				inCSI = false
			}
		}
		if !skipOutput {
			output = append(output, r)
		}
		prev = r
	}

	return append(output, csi...)
}
