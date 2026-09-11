#pragma once
using namespace std;

void info(string ip,string type,string Fport,string Lport){
string fulltypename;
	if(type =="tcs"){
	fulltypename="TCP Connect Scan";
	}
	if(type=="scs"){
	fulltypename="SYN Connect Scan";
	}
	if(type=="ucs"){
	fulltypename="UDP Connect Scan";
	}
	if(type=="acs"){
	fulltypename="ACK Connect Scan";
	}
	if(type=="fcs"){
	fulltypename="FIN Connect Scan";
	}
	if(type=="ncs"){
	fulltypename="NULL Connect Scan";
	}
	if(type=="xmascs"){
	fulltypename="XMAS Connect Scan";
	}

cout<<"IP Target ->  < "<<ip<<" >\n";
cout<<"Ports     ->  < "<<Fport<<"-"<<Lport<<" >\n";
cout<<"Type Scan ->  < "<<type<<"-"<<fulltypename<<" >\n";
}
