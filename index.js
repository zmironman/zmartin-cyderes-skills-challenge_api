const axios = require('axios');
const config = require('./config');

let WhoIsAPIKey = config.apikeys.whois;
let VirusTotalAPIKey = config.apikeys.virustotal;
let GeoDataAPIKey = config.apikeys.geodata;

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
            result.push(['whois', await getWhois(event.ip)]);
        }
        if (event.geodata) {
            result.push(['geo', await getGeoData(event.ip)]);
        }
        if (event.virustotal) {
            result.push(['virustotal', await getVirusTotal(event.ip)]);
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