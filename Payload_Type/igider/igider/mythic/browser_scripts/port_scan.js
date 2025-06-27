function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        try{
            // Find the last response that looks like JSON
            let jsonResponse = null;
            for(let i = responses.length - 1; i >= 0; i--){
                const response = responses[i].trim();
                if(response.startsWith('{') && response.endsWith('}')){
                    jsonResponse = response;
                    break;
                }
            }
            
            if(!jsonResponse){
                // No JSON found, return all responses as plain text
                const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
            
            let data = JSON.parse(jsonResponse);
           
            if(data.error){
                return {'plaintext': data.error};
            }
           
            let output = "";
            output += "=== Port Scan Results ===\n";
            output += `Scan Start: ${data.scan_start}\n`;
            output += `Scan End: ${data.scan_end}\n`;
            output += `Targets: ${data.summary.total_hosts}\n`;
            output += `Ports: ${data.summary.total_ports}\n\n`;
           
            // Display results for each host
            for(let host in data.results){
                let hostData = data.results[host];
                output += `Host: ${host}\n`;
                output += `Total Scanned: ${hostData.total_scanned}\n`;
                output += `Open Ports: ${hostData.open_ports.length}\n`;
                output += `Closed Ports: ${hostData.closed_ports}\n`;
                output += `Filtered Ports: ${hostData.filtered_ports}\n\n`;
               
                if(hostData.open_ports.length > 0){
                    output += "Open Ports:\n";
                    output += "PORT\tSTATE\tSERVICE\n";
                    output += "----\t-----\t-------\n";
                   
                    for(let portInfo of hostData.open_ports){
                        output += `${portInfo.port}\t${portInfo.state}\t${portInfo.service}\n`;
                    }
                    output += "\n";
                }
            }
           
            return {'plaintext': output};
           
        }catch(error){
            console.error("Error parsing port scan results:", error);
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    }else if(task.status === "processed"){
        if(responses.length > 0){
            try{
                // Show intermediate results
                let output = "Port Scan in Progress...\n\n";
               
                for(let i = 0; i < responses.length; i++){
                    if(responses[i].includes("Completed scan for")){
                        output += responses[i] + "\n";
                    }
                }
               
                return {"plaintext": output};
            }catch(error){
                return {"plaintext": "Port scan running..."};
            }
        }
        return {"plaintext": "Initializing port scan..."}
    }else{
        return {"plaintext": "No response yet from agent..."}
    }
}