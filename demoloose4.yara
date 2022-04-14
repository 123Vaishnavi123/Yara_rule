rule trojanloosedemo4strings
{
         meta: 
		   author="vashnavi"
		   malware="trojan sample"
		   
		   strings:
		           $a="??3@YAXPAX@Z"
                           $b=".?AVtype_info@@"
			   $c= "ShellExecute"			 
                           $d= "kwur9*-qus/achfs,`lo.hs(vyv"
			 
			 
			 condition:
			  ($a and $b and $c and $d)
			 
} 
