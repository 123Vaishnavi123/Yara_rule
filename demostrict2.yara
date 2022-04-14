import "hash"
rule malware
{

	meta:
		description: "this rule is to detect malware"
        condition:
                hash.md5(0, filesize)=="60ff78514d6df20c6e82b7b777151c5c"
}