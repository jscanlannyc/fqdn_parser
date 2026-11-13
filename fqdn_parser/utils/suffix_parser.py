import re
import logging
import requests
from datetime import datetime
from bs4 import BeautifulSoup
from fqdn_parser.utils.trie import Trie

_logger = logging.getLogger(__name__)

# links to iana and icann sources for TLD / suffix information
TLD_LIST_JSON_URL = "https://data.iana.org/TLD/v1/tlds.json"
SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# manually parse all IANA TLD pages and pulled registration dates. This takes quite a while to do
# so shipping this resource file with the source
tld_reg_date_resource = "tld_reg_dates_v2.txt"

PUNY_PREFIX = "xn--"


def build_suffixes():
    _suffix_trie = _load_json_tlds()
    _load_manual_tlds(_suffix_trie)
    _enrich_tld_suffixes(_suffix_trie)
    # create a punycode suffix reverse index
    _puny_suffixes = {}
    root_tlds = _suffix_trie.root.children
    for tld_node in root_tlds.values():
        if tld_node.puny:
            _puny_suffixes[tld_node.puny] = tld_node.label
    return _suffix_trie, _puny_suffixes


def _load_json_tlds() -> Trie:
    """On October 15th, 2026, IANA updated their table formatting again, but
    also introduced a json-file which contains data the previous parser used.

    Simultaneously, they introduced a JSON file which provides most of the same
    data needed for this script to run. This ingests that JSON file.

    Reference:
    https://www.iana.org/domains/root/db
    """
    trie = Trie()
    response = requests.get(TLD_LIST_JSON_URL)
    PUNY_TLD_PATTERN = "^xn--.*$"
    if response.status_code != 200:
        raise requests.HTTPError(f"{TLD_LIST_JSON_URL} error {response.status_code}")
    tld_json = response.json()["domains"]
    for tld_entry in tld_json:
        # the shorthand domain, without a period (ex. "com", "net", "org")
        tld = tld_entry["name"]
        # whether the domain is a country code, generic suffix, or marked for special use
        tld_type = tld_entry["type"]
        # if the tld is active, retired, pending approval
        status = tld_entry["status"]
        if status not in ["retired"]:
            # the name of the organization that manages the tld
            registry = None
            if tld_entry["manager"] and "organization" in tld_entry["manager"]:
                registry = tld_entry["manager"]["organization"]
            # if the domain is represented in unicode, get the punyicode representation,
            # prefixed by 'xn--' for that domain.
            puny_tld = None
            if re.search(PUNY_TLD_PATTERN, tld):
                puny_tld = tld
                # the actual unicode representation of the punycode
                tld = tld_entry["ulabel"]
            # when the tld was assigned to its manager, if it was delegated for management outside icann
            tld_delegation_date = tld_entry["events"]["delegation"]
            if not tld_delegation_date:
                _logger.warning(f"Delegation date not found for TLD '{tld}'")
            trie.insert_tld_node(tld, puny_tld, tld_type, registry, tld_delegation_date)
    return trie


def _load_manual_tlds(_suffix_trie: Trie):
    """Add in any extra TLDs manually"""
    # add in the onion TLD manually
    tld = "onion"
    _suffix_trie.insert_tld_node(
        tld,
        None,
        "host_suffix",
        "Tor",
        datetime.strptime("2015-09-15", "%Y-%m-%d").date(),
    )


def _enrich_tld_suffixes(_suffix_trie: Trie):
    """Pull in all known public suffixes
    TODO: A lot of these are not considered multi label TLDs, like "co.uk", but instead are suffixes used
          by dynamic DNS providers. I need to figure out a way to differentiate the two and add dynamic dns
          as property on a suffix.
    """
    response = requests.get(SUFFIX_LIST_URL)
    if response.status_code != 200:
        raise requests.HTTPError(f"{SUFFIX_LIST_URL} error {response.status_code}")
    suffix_list = response.content.decode("utf-8")
    suffix_list = suffix_list.split("\n")

    # add each sub suffix to its parent TLD
    is_private_suffix = False
    for i, line in enumerate(suffix_list):
        if line == "// ===BEGIN PRIVATE DOMAINS===":
            # set flag and continue
            is_private_suffix = True
            continue
        elif len(line) == 0 or line[:3] == "// ":
            # skip comments
            continue
        suffix = line.strip()
        # strip out wildcards
        if suffix[:2] == "*." or suffix[:2] == "!.":
            suffix = suffix[2:]
        if "." in suffix:
            # todo: check for puny tld
            # tld = suffix[suffix.rindex(".") + 1:]
            # add suffix to trie tree
            _suffix_trie.insert_suffix_node(suffix, is_private_suffix)
        else:
            # There are 9 IDN TLDs in the suffix list that are NOT listed in the iana root zone database
            # - so adding them here (they are all country code IDN TLDs)
            if _suffix_trie.get_node([suffix]) is None:
                print(
                    f"WARNING: Suffix '{suffix}' found in Public Suffix List is not in IANA root zone database. Manually adding suffix to list of root TLDs"
                )
                # parse out the puny code from the previous line if possible
                previous_line = suffix_list[i - 1]
                puny = None
                if "// xn--" in previous_line:
                    puny = previous_line[3:]
                    puny = puny[: puny.index(" ")]
                _suffix_trie.insert_tld_node(suffix, puny, "country-code", None, None)
