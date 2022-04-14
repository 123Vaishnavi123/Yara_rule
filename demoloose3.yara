rule trojanloosedemo3strings
{
    meta: 
		   author="vaishnavi"
		   description="trojan sample"
		   
    strings:
	         $a= "svchost.exe"
            
	         $b= "www.1535ss.com:8080" 
			 
	       	 $c= "??3@YAXPAX@Z"
			 
     condition:
			  ($a and $b and $c)
			 
}