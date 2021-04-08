global ip_list: table[addr] of set[string];
event http_ua(c: connection, name: string, value: string)
{
	local ip :addr =c$id$orig_h;
	if(name=="USER-AGENT")
	{
		if(ip !in ip_list)
			ip_list[ip]=set(to_lower(value));
		else
			add ip_list[ip][to_lower(value)];
	}
}
 
event zeek_done()
{	
	for (sourceip in ip_list)
	{
		if(|ip_list[sourceip]|>3)
			print (fmt("%s is a proxy",sourceip));
	}
}