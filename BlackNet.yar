rule Black_Net 
{
	meta : 
		author = "psyb3rm0nk"
		malware_family = "black_net"
		sha256 = "2E4D8723602C5FFC6409DCEB0CB4CED2E749E374A0FCD41FE92E0FD50F817C5B"
		date = "2025/01/03"
		description = "just a experiment for .net malware"

	strings :
		
		$f1 = "svchost.exe"
		$f2 = "schtasks.exe"
		$f3 = "WindowsUpdate.exe"

		$s1 = "AntiWD"
		$s2 = "AntiVM"
		$s3 = "Anti_Debugging"
		$s4 = "GetAntiVirus"

		$st1 = "StealFFCookies"
		$st2 = "StealPasswords"
		$st3 = "StealChromeCookies"

	condition:
		uint16(0) == 0x5A4D AND 2 of ($f*) and 3 of ($s*) and 3 of ($st*)





}