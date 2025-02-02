rule Detecting_lumma_file
{
    meta:

        author = "pysb3rm0nk"
        malware_family = "lumma"
        file = "/3A6E5838A03790664F3653D6EEDAE016D0EB6E2006EF6E870281D18A697FA9D8"
        date = "08/01/2025"

    strings:

        $fi1 = "login.exe" nocase
        $fi2 = "powershell.exe" nocase
        $fi3 = "update.exe" nocase
        $fi4 = "CompPkgSrv.exe" nocase

        $s1 = "Login" nocase
        $s2 = "Password" nocase
        $s3 = "get photo"

    condition:
    
        uint16(0) == 0x5A4D and all of ($fi*) and all of ($s*)

}