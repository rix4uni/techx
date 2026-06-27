package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.1.0"

func PrintVersion() {
	fmt.Printf("Current techfinder version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
   __               __     ____ _             __           
  / /_ ___   _____ / /_   / __/(_)____   ____/ /___   _____
 / __// _ \ / ___// __ \ / /_ / // __ \ / __  // _ \ / ___/
/ /_ /  __// /__ / / / // __// // / / // /_/ //  __// /    
\__/ \___/ \___//_/ /_//_/  /_//_/ /_/ \__,_/ \___//_/
`
	fmt.Printf("%s\n%50s\n\n", banner, "Current techfinder version "+version)
}
