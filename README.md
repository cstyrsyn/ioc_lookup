# IOC Lookup Tool 

This tool allows you to look up details associated with various types of Internet data, including IP addresses, URLs, email addresses and file hashes. It retrieves information from multiple sources such as VirusTotal, AbuseIPDB and IPQualityScore. The tool provides additional features such as sandbox examination results for file hashes from VirusTotal, and analysis of data to provide colour-coded result display for better usability.  

## Prerequisites 
The system must have either Windows 11 or Unix/Linux like operating system for full colour experience.

Make sure to have the following python libraries installed:
- Colorama

## Usage 

The script ioc.py is the main file to run and it accepts the following arguments: 

- IP: An IPv4 address you desire to look up information about
- URL: A URL you desire to look up information about
- Hash: A file hash you desire to look up information about
- Email: An email address you desire to look up information about
- Lookback: Number of days the user wants to look back into the history (optional)
 
```
python ioc.py -ip <ip address> -url <url> -hash <hash> -email <email> -lookback <number of days>
```
Note: For API keys of the mentioned services, make sure to provide the keys and run the script `add-api.ps1`. This will add them as OS environment variables rather than hard coding them into the script.
If the keys are not present then you'll get an error stating "Keys not present, have you ran add-api.ps1?". 

## Future Improvements 
Work in progress on enhancing error handling and adding more error checking functionality. 

## License 
Tool is open source and free to use. 
