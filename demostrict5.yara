import "hash"

rule trojanStatic 

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "689ff2c6f94e31abba1ddebf68be810e"
 
 }