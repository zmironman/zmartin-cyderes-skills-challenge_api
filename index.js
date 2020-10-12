const axios = require('axios');

let WhoIsAPIKey = process.env.whoiskey;
let VirusTotalAPIKey = process.env.virustotalkey;
let GeoDataAPIKey = process.env.geodatakey;

async function getWhois(ip) {
    let result = {};
    await axios.get(` https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
        {headers: {'x-apikey': WhoIsAPIKey}})
        .then(response => {
                result = response.data.data;
            }
        )
        .catch(err => {
                console.error(err.data);
            }
        );
    return result;
}


async function getGeoData(ip) {
    let result = {};
    await axios.get(`http://api.ipstack.com/${ip}?access_key=${GeoDataAPIKey}`)
        .then(response => {
                if(response.success === false){
                    console.error(response.data.error);
                    result = null;
                }
                result = response.data;
            }
        )
        .catch(err => {
                console.error(err.data);
            }
        );
    return result;
}


async function getVirusTotal(ip) {
    let result = {};
    await axios.get(`https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=${VirusTotalAPIKey}&ip=${ip}`)
        .then(response => {
                result = response.data;
            }
        )
        .catch(err => {
                console.error(err.data);
            }
        );
    return result;
}

async function getResults(event) {
    let result = [];
    if (event.ip) {
        if (event.whois) {
            result.push(['Whois', await getWhois(event.ip)]);
        }
        if (event.geodata) {
            result.push(['Geodata', await getGeoData(event.ip)]);
        }
        if (event.virustotal) {
            result.push(['Virus Total', await getVirusTotal(event.ip)]);
        }
    }
    return result;
}

const main = event => {
    if (event === undefined)
        return null;
    return getResults(event);
};

exports.handler = main;