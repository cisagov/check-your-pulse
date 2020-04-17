# check-your-pulse #

[![GitHub Build Status](https://github.com/cisagov/check-your-pulse/workflows/build/badge.svg)](https://github.com/cisagov/check-your-pulse/actions)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/check-your-pulse/badge.svg?branch=master)](https://coveralls.io/github/cisagov/check-your-pulse?branch=master)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/check-your-pulse.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/check-your-pulse/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/check-your-pulse.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/check-your-pulse/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/check-your-pulse/master/badge.svg)](https://snyk.io/test/github/cisagov/check-your-pulse)

This utility can help determine if indicators of compromise (IOCs) exist in the
 log files of a Pulse Secure VPN Appliance for
[CVE-2019-11510](https://nvd.nist.gov/vuln/detail/CVE-2019-11510).

The Cybersecurity and Infrastructure Security Agency (CISA) has seen many organ
izations breached despite patching their appliance because of Active Directory
credentials (to include Domain Admin) harvested prior to patching. Details are
available in Alert [AA20-107A](https://www.us-cert.gov/ncas/alerts/aa20-107a).
This tool may help organizations locate exploitation attempts in their logs and
 assess their risk based on the results. If exploitation attempts are located p
rior to the date of patch, it may be necessary to carefully watch for unauthori
zed connections and perform a full domain password reset.

The IOCs included in this tool are TLP:WHITE. Adding more indicators from open-
source or commercial vendors may improve the effectiveness of this tool.

The tool works by looking for IOCs (strings, Internet Protocol [IP] addresses,
and user agents) associated with Threat Actors exploiting this vulnerability in
 the wild.

## Requirements ##

Python versions 3.6 and above.  Note that Python 2 is **not** supported.

## Installation ##

### PULSE SECURE SETUP ###

> If unauthenticated logging was not enabled prior to patching, you will be rel
>iant on user agent strings and IPs, which are much less reliable indicators.

Detailed instructions regarding pulse secure setup can be found
[here](https://docs.pulsesecure.net/WebHelp/PCS/8.3R3/Content/PCS/PCS_AdminGuide_8.3/Configuring_Events_to_Log.htm).

### CHECK-YOUR-PULSE ###

```console
git clone https://github.com/cisagov/check-your-pulse.git
cd check-your-pulse
```

## Usage ##

```HTML
Download the logs from web console
```

Instructions can be found
[here](https://docs.pulsesecure.net/WebHelp/PCS/8.3R3/Content/PCS/PCS_AdminGuide_8.3/Displaying_System_Logs.htm)
 for version 8.3 of the Pulse Connect Secure.

```console
$ python3 ./app.py --path <path to .events and .access files, defaults to ./>

OUTPUT
```

Detailed usage information can be viewed with:

```console
$ python3 ./app.py -h

usage: app.py [-h] [-r RAW] [-c CSV] [-j JSON] [-p PATH] [-n NUMEVENTS]

optional arguments:
  -h, --help            show this help message and exit
  -r RAW, --raw RAW     Dumps the output to a human readable file.
  -c CSV, --csv CSV     Writes output to a .csv file. Needs to be provided the
                        name to save as.
  -j JSON, --json JSON  Writes output to a .json file. Needs to be provided
                        the name to save as.
  -p PATH, --path PATH  Path to the folder containing .access and .events.
  -n NUMEVENTS, --numevents NUMEVENTS
                        Number of events to print in the quick summary
                        (default 10)

```

For more information about this vulnerability see:
[https://nvd.nist.gov/vuln/detail/CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)

## Issues ##

If you have issues using the code, open an issue on the repository!

You can do this by clicking "Issues" at the top and clicking "New Issue" on the
 following page.

## Contributing ##

We welcome contributions!  Please see [here](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.

## Legal Disclaimer ##

NOTICE

This software package (“software” or “code”) was created by the United States G
overnment and is not subject to copyright. You may use, modify, or redistribute
 the code in any manner. However, you may not subsequently copyright the code a
s it is distributed. The United States Government makes no claim of copyright o
n the changes you effect, nor will it will it restrict your distribution of bon
a fide changes to the software. If you decide to update or redistribute the cod
e, please include this notice with the code. Where relevant, we ask that you cr
edit the Cybersecurity and Infrastructure Security Agency with the following st
atement: “Original code developed by the Cybersecurity and Infrastructure Secur
ity Agency (CISA), U.S. Department of Homeland Security.”

USE THIS SOFTWARE AT YOUR OWN RISK. THIS SOFTWARE COMES WITH NO WARRANTY, EITHE
R EXPRESS OR IMPLIED. THE UNITED STATES GOVERNMENT ASSUMES NO LIABILITY FOR THE
 USE OR MISUSE OF THIS SOFTWARE OR ITS DERIVATIVES.

THIS SOFTWARE IS OFFERED “AS-IS.” THE UNITED STATES GOVERNMENT WILL NOT INSTALL
, REMOVE, OPERATE OR SUPPORT THIS SOFTWARE AT YOUR REQUEST. IF YOU ARE UNSURE O
F HOW THIS SOFTWARE WILL INTERACT WITH YOUR SYSTEM, DO NOT USE IT.

--
