package output

import "golang.org/x/crypto/ssh/terminal"

type Output struct {
	width int
}

func New() *Output {
	width, _, err := terminal.GetSize(0)
	if err != nil {
		width = 80
	}
	return &Output{
		width: width,
	}
}

func (o *Output) Title(title string) {

}
