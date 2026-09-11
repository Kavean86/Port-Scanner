#pragma once



// Include the service mapping definitions

#include "Service_mapping.h"



// Print information about all detected open ports

void print_results(string type){



// Iterate through the list of detected open ports

for(int i=0;i<openports.size();i++){



// Display the port number, source port, and detected service

cout<<openports[i]<<" open"<<"| source port: "<<sourceports[i]<<" | Service : "<<services[openports[i]]<<endl;



// FIN, NULL, and XMAS scans cannot reliably distinguish

// between an open port and a filtered port

if(type=="fcs" || type=="ncs" || type=="xmascs"){



// Display a warning that the port may be open or filtered

cout << "\033[33mPort is open or Filter\033[0m\n";

}

}



// Clear the stored open-port results

openports.clear();



// Clear the stored source-port results

sourceports.clear();



// Exit the function

return;

}
