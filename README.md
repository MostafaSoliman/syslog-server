a simple syslog server that will monitor the packets pass through the any any rule , and compare each packet with the forbidden access excel sheet .
if a legal packet is seen it will record it , when closing the server it will convert all the legal caught packets into FW rules that you can apply at the top of your access list to match the traffic  , by running the server for sufficient time you will be able to collect all the legal traffic, at then deleting the any any rule should be no problem.


read the article  at https://www.linkedin.com/pulse/how-solve-permit-ip-any-firewall-rule-without-your-business-soliman?published=t
