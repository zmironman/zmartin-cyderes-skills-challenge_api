const axios = require('axios');
const config = require('config');

const WhoIsAPIKey = config.get('apikeys.whois');
const VirusTotalAPIKey = config.get('apikeys.virustotal');
const GeoDataAPIKey = config.get('apikeys.geodata');

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

async function getResults({ip}) {
    return [
        ['whois', await getWhois(ip)],
        ['geo', await getGeoData(ip)],
        ['virustotal', await getVirusTotal(ip)]
    ]
}

const main = event => {
    console.log('Event: ', event);
    if (event === undefined)
        return null;
    return getResults(event);
};

exports.handler = main;