rule WANNAHUSKY {

	meta:
		last_updated = "2022-01-15"
		author = "Crypt0ace"
		description = "YARA Rules for WannaHusky Ransomware"

	strings:
		$string1 = "tree" ascii
		$string2 = "ps1.ps1" ascii
		$string3 = "powershell" ascii
		$string4 = "WANNAHUSKY.png" ascii
		$string5 = "cosmo.WANNAHUSKY" ascii
		$string6 = "cosmo.jpeg" ascii
		$PE_magic_byte = "MZ"
		
	condition:
		$PE_magic_byte at 0 and
		($string1 and $string2 and $string3 and $string4 and $string5 and
$string6)
}