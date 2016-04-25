// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2016 Strength In Numbers Foundation
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "util.h"
#include "sync.h"
#include "ui_interface.h"
#include "base58.h"
#include "bitcoinrpc.h"
#include "db.h"

#undef printf
#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <list>

#define printf OutputDebugStringF

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

void ThreadRPCServer2(void* parg);

static std::string strRPCUserColonPass;

const Object emptyobj;

void ThreadRPCServer3(void* parg);

static inline unsigned short GetDefaultRPCPort()
{
    return GetBoolArg("-testnet", false) ? 43590 : 53590;
}

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected,
                  bool fAllowNull)
{
    BOOST_FOREACH(const PAIRTYPE(string, Value_type)& t, typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64 AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > MAX_MONEY)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

int64 AmountFromZeroValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount < 0.0 || dAmount > MAX_MONEY)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(int64 amount)
{
    return (double)amount / (double)COIN;
}

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}



///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
    string strRet;
    set<rpcfn_type> setDone;
    printf("bitcoinrpc.cpp / CRPCTable::help(\"%s\")\n", strCommand.c_str());
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        printf("strMethod = %s\n", strMethod.c_str());
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        printf("try\n");
        try
        {
            Array params;
            rpcfn_type pfn = pcmd->actor;
            string strHelp = pcmd->help;

            if (strHelp != "") {
                if (strCommand == "")
                    if (strHelp.find('\n') != string::npos)
                        strHelp = strHelp.substr(0, strHelp.find('\n'));
                strRet += strHelp + "\n";
            } else {
                printf("pfn = pcmd->actor\n");
                if (setDone.insert(pfn).second) {
                    printf("calling pointer\n");
                    pcmd->actor(params, true);
 //             (*pfn)(params, true);
                }
            }
        }
        catch (std::exception& e)
        {
            printf("catch\n");
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        return NULL;
/*dvd        throw runtime_error(
            "help [command]\n"
            "List commands, or get help for a command.");
*/
    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        return NULL;
/*dvd        throw runtime_error(
            "stop <detach>\n"
            "<detach> is true or false to detach the database or not for this stop only\n"
            "Stop 2GiveCoin server (and possibly override the detachdb config value).");
*/
    // Shutdown will take long enough that the response should get back
    if (params.size() > 0)
        bitdb.SetDetach(params[0].get_bool());
    StartShutdown();
    return "2GiveCoin server stopping";
}



//
// Call Table
//


static const CRPCCommand vRPCCommands[] =
{ //name                      function                 safemd  unlocked   help
  //------------------------  -----------------------  ------  --------   -----
  { "addmultisigaddress",     &addmultisigaddress,     false,  false,     "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\nAdd a nrequired-to-sign multisignature address to the wallet\"\neach key is a 2GiveCoin address or hex-encoded public key\nIf [account] is specified, assign address to [account]." },
  { "addnode",                &addnode,                true,   true,      "addnode <node> <add|remove|onetry>\nAttempts add or remove <node> from the addnode list or try a connection to <node> once." },
  { "backupwallet",           &backupwallet,           true,   false,     "backupwallet <destination>\nSafely copies wallet.dat to destination, which can be a directory or a path with filename." },
  { "checkwallet",            &checkwallet,            false,  true,      "checkwallet\nCheck wallet for integrity.\n" },
  { "createrawtransaction",   &createrawtransaction,   false,  false,     "createrawtransaction [{\"txid\":txid,\"vout\":n},...] {address:amount,...}\nCreate a transaction spending given inputs\n(array of objects containing transaction id and output number),\nsending to given address(es).\nReturns hex-encoded raw transaction.\nNote that the transaction's inputs are not signed, and\nit is not stored in the wallet or transmitted to the network." },
  { "decoderawtransaction",   &decoderawtransaction,   false,  false,     "decoderawtransaction <hex string>\nReturn a JSON object representing the serialized, hex-encoded transaction." },
  { "dumpprivkey",            &dumpprivkey,            false,  false,     "dumpprivkey <2GiveCoinaddress>\nReveals the private key corresponding to <2GiveCoinaddress>." },
  { "encryptwallet",          &encryptwallet,          false,  false,     "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>." },
  { "getaccount",             &getaccount,             false,  false,     "getaccount <2GiveCoinaddress>\nReturns the account associated with the given address." },
  { "getaccountaddress",      &getaccountaddress,      true,   false,     "getaccountaddress <account>\nReturns the current 2GiveCoin address for receiving payments to this account." },
  { "getaddednodeinfo",       &getaddednodeinfo,       true,   true,      "getaddednodeinfo <dns> [node]\nReturns information about the given added node, or all added nodes\n(note that onetry addnodes are not listed here)\nIf dns is false, only a list of added nodes will be provided,\notherwise connected information will also be available." },
  { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false,     "getaddressesbyaccount <account>\nReturns the list of addresses for the given account." },
  { "getbalance",             &getbalance,             false,  false,     "getbalance [account] [minconf=1]\nIf [account] is not specified, returns the server's total available balance.\nIf [account] is specified, returns the balance in the account." },
  { "getblock",               &getblock,               false,  false,     "getblock <hash> [txinfo]\ntxinfo optional to print more detailed tx info\nReturns details of a block with given block-hash." },
  { "getblockbynumber",       &getblockbynumber,       false,  false,     "getblockbynumber <number> [txinfo]\ntxinfo optional to print more detailed tx info\nReturns details of a block with given block-number." },
  { "getblockcount",          &getblockcount,          true,   false,     "getblockcount\nReturns the number of blocks in the longest block chain." },
  { "getblockhash",           &getblockhash,           false,  false,     "getblockhash <index>\nReturns hash of block in best-block-chain at <index>." },
  { "getblocktemplate",       &getblocktemplate,       true,   false,     "getblocktemplate [params]\nReturns data needed to construct a block to work on:\n  \"version\" : block version\n  \"previousblockhash\" : hash of current highest block\n  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n  \"coinbaseaux\" : data that should be included in coinbase\n  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n  \"target\" : hash target\n  \"mintime\" : minimum timestamp appropriate for next block\n  \"curtime\" : current timestamp\n  \"mutable\" : list of ways the block template may be changed\n  \"noncerange\" : range of valid nonces\n  \"sigoplimit\" : limit of sigops in blocks\n  \"sizelimit\" : limit of block size\n  \"bits\" : compressed target of next block\n  \"height\" : height of the next block\nSee https://en.bitcoin.it/wiki/BIP_0022 for full specification." },
  { "getcheckpoint",          &getcheckpoint,          true,   false,     "getcheckpoint\nShow info of synchronized checkpoint." },
  { "getconnectioncount",     &getconnectioncount,     true,   false,     "getconnectioncount\nReturns the number of connections to other nodes." },
  { "getdifficulty",          &getdifficulty,          true,   false,     "getdifficulty\nReturns the difficulty as a multiple of the minimum difficulty." },
  { "getgenerate",            &getgenerate,            true,   false,     "getgenerate\nReturns true or false." },
  { "gethashespersec",        &gethashespersec,        true,   false,     "gethashespersec\nReturns a recent hashes per second performance measurement while generating." },
  { "getinfo",                &getinfo,                true,   false,     "getinfo\nReturns an object containing various state info." },
  { "getmininginfo",          &getmininginfo,          true,   false,     "getmininginfo\nReturns an object containing mining-related information." },
  { "getmint",                &getmint,                true,   false,     "getmint\nReturns true or false" },
  { "getnewaddress",          &getnewaddress,          true,   false,     "getnewaddress [account]\nReturns a new 2GiveCoin address for receiving payments.\nIf [account] is specified (recommended), it is added to the address book\nso payments received with the address will be credited to [account]." },
  { "getnewpubkey",           &getnewpubkey,           true,   false,     "getnewpubkey [account]\nReturns new public key for coinbase generation." },
  { "getpeerinfo",            &getpeerinfo,            true,   false,     "getpeerinfo\nReturns data about each connected network node." },
  { "getrawmempool",          &getrawmempool,          true,   false,     "getrawmempool\nReturns all transaction ids in memory pool." },
  { "getrawtransaction",      &getrawtransaction,      false,  false,     "getrawtransaction <txid> [verbose=0]\nIf verbose=0, returns a string that is\nserialized, hex-encoded data for <txid>.\nIf verbose is non-zero, returns an Object\nwith information about <txid>." },
  { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false,     "getreceivedbyaccount <account> [minconf=1]\nReturns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations." },
  { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false,     "getreceivedbyaddress <2GiveCoinaddress> [minconf=1]\nReturns the total amount received by <2GiveCoinaddress> in transactions with at least [minconf] confirmations." },
  { "gettransaction",         &gettransaction,         false,  false,     "gettransaction <txid>\nGet detailed information about <txid>" },
  { "getwork",                &getwork,                true,   false,     "getwork [data]\nIf [data] is not specified, returns formatted hash data to work on:\n  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n  \"data\" : block data\n  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n  \"target\" : little endian hash target\nIf [data] is specified, tries to solve the block and returns true if it was successful." },
  { "getworkex",              &getworkex,              true,   false,     "getworkex [data, coinbase]\nIf [data, coinbase] is not specified, returns extended work data.\n" },
  { "help",                   &help,                   true,   true,      "help [command]\nList commands, or get help for a command." },
  { "importprivkey",          &importprivkey,          false,  false,     "importprivkey <2GiveCoinprivkey> [label]\nAdds a private key (as returned by dumpprivkey) to your wallet." },
  { "keypoolrefill",          &keypoolrefill,          true,   false,     "keypoolrefill\nFills the keypool." },
  { "listaccounts",           &listaccounts,           false,  false,     "listaccounts [minconf=1]\nReturns Object that has account names as keys, account balances as values." },
  { "listaddressgroupings",   &listaddressgroupings,   false,  false,     "listaddressgroupings\nLists groups of addresses which have had their common ownership\nmade public by common use as inputs or as the resulting change\nin past transactions" },
  { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false,     "listreceivedbyaccount [minconf=1] [includeempty=false]\n[minconf] is the minimum number of confirmations before payments are included.\n[includeempty] whether to include accounts that haven't received any payments.\nReturns an array of objects containing:\n  \"account\" : the account of the receiving addresses\n  \"amount\" : total amount received by addresses with this account\n  \"confirmations\" : number of confirmations of the most recent transaction included" },
  { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false,     "listreceivedbyaddress [minconf=1] [includeempty=false]\n[minconf] is the minimum number of confirmations before payments are included.\n[includeempty] whether to include addresses that haven't received any payments.\nReturns an array of objects containing:\n  \"address\" : receiving address\n  \"account\" : the account of the receiving address\n  \"amount\" : total amount received by the address\n  \"confirmations\" : number of confirmations of the most recent transaction included" },
  { "listsinceblock",         &listsinceblock,         false,  false,     "listsinceblock [blockhash] [target-confirmations]\nGet all transactions in blocks since block [blockhash], or all transactions if omitted" },
  { "listtransactions",       &listtransactions,       false,  false,     "listtransactions [account] [count=10] [from=0]\nReturns up to [count] most recent transactions skipping the first [from] transactions for account [account]." },
  { "listunspent",            &listunspent,            false,  false,     "listunspent [minconf=1] [maxconf=9999999]  [\"address\",...]\nReturns array of unspent transaction outputs\nwith between minconf and maxconf (inclusive) confirmations.\nOptionally filtered to only include txouts paid to specified addresses.\nResults are an array of Objects, each of which has:\n{txid, vout, scriptPubKey, amount, confirmations}" },
  { "makekeypair",            &makekeypair,            false,  true,      "makekeypair [prefix]\nMake a public/private key pair.\n[prefix] is optional preferred prefix for the public key.\n" },
  { "move",                   &movecmd,                false,  false,     "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\nMove from one account in your wallet to another." },
  { "repairwallet",           &repairwallet,           false,  true,      "repairwallet\nRepair wallet if checkwallet reports any problem.\n" },
  { "resendtx",               &resendtx,               false,  true,      "resendtx\nRe-send unconfirmed transactions.\n" },
  { "reservebalance",         &reservebalance,         false,  true,      "reservebalance [<reserve> [amount]]\n<reserve> is true or false to turn balance reserve on or off.\n<amount> is a real and rounded to cent.\nSet reserve amount not participating in network protection.\nIf no parameters provided current setting is printed.\n" },
  { "sendalert",              &sendalert,              false,  false,     "sendalert <message> <privatekey> <minver> <maxver> <priority> <id> [cancelupto]\n<message> is the alert text message\n<privatekey> is hex string of alert master private key\n<minver> is the minimum applicable internal client version\n<maxver> is the maximum applicable internal client version\n<priority> is integer priority number\n<id> is the alert id\n[cancelupto] cancels all alert id's up to this number\nReturns true or false." },
  { "sendfrom",               &sendfrom,               false,  false,     "sendfrom <fromaccount> <to2GiveCoinaddress> <amount> [minconf=1] [comment] [comment-to]\n<amount> is a real and is rounded to the nearest 0.000001" }, // + HelpRequiringPassphrase()
  { "sendmany",               &sendmany,               false,  false,     "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\namounts are double-precision floating point numbers" },
  { "sendrawtransaction",     &sendrawtransaction,     false,  false,     "sendrawtransaction <hex string>\nSubmits raw transaction (serialized, hex-encoded) to local node and network." },
  { "sendtoaddress",          &sendtoaddress,          false,  false,     "sendtoaddress <2GiveCoinaddress> <amount> [comment] [comment-to]\n<amount> is a real and is rounded to the nearest 0.000001" },
  { "setaccount",             &setaccount,             true,   false,     "setaccount <2GiveCoinaddress> <account>\nSets the account associated with the given address." },
  { "setdefaultaddress",      &setdefaultaddress,      true,   false,     "setdefaultaddress <2GiveCoinaddress>\nSets the default receive address in the wallet." },
  { "setgenerate",            &setgenerate,            true,   false,     "setgenerate <generate> [genproclimit]\n<generate> is true or false to turn generation on or off.\nGeneration is limited to [genproclimit] processors, -1 is unlimited." },
  { "setmint",                &setmint,                true,   false,     "setmint <stake>\n<stake> is true or false to turn proof of stake minting on or off." },
  { "settxfee",               &settxfee,               false,  false,     "settxfee <amount>\n<amount> is a real and is rounded to the nearest 0.01" },
  { "signmessage",            &signmessage,            false,  false,     "signmessage <2GiveCoinaddress> <message>\nSign a message with the private key of an address" },
  { "signrawtransaction",     &signrawtransaction,     false,  false,     "signrawtransaction <hex string> [{\"txid\":txid,\"vout\":n,\"scriptPubKey\":hex},...] [<privatekey1>,...] [sighashtype=\"ALL\"]\nSign inputs for raw transaction (serialized, hex-encoded).\n" },
  { "stop",                   &stop,                   true,   true,      "stop <detach>\n<detach> is true or false to detach the database or not for this stop only\nStop 2GiveCoin server (and possibly override the detachdb config value)." },
  { "submitblock",            &submitblock,            false,  false,     "submitblock <hex data> [optional-params-obj]\n[optional-params-obj] parameter is currently ignored.\nAttempts to submit new block to network.\nSee https://en.bitcoin.it/wiki/BIP_0022 for full specification." },
  { "validateaddress",        &validateaddress,        true,   false,     "validateaddress <2GiveCoinaddress>\nReturn information about <2GiveCoinaddress>." },
  { "validatepubkey",         &validatepubkey,         true,   false,     "validatepubkey <2GiveCoinpubkey>\nReturn information about <2GiveCoinpubkey>." },
  { "verifymessage",          &verifymessage,          false,  false,     "verifymessage <2GiveCoinaddress> <signature> <message>\nVerify a signed message" },
  { "walletlock",             &walletlock,             true,   false,     "walletlock\nRemoves the wallet encryption key from memory, locking the wallet.\nAfter calling this method, you will need to call walletpassphrase again\nbefore being able to call any methods which require the wallet to be unlocked." },
  { "walletpassphrase",       &walletpassphrase,       true,   false,     "walletpassphrase <passphrase> <timeout> [mintonly]\nStores the wallet decryption key in memory for <timeout> seconds.\nmintonly is optional true/false allowing only block minting." },
  { "walletpassphrasechange", &walletpassphrasechange, false,  false,     "walletpassphrasechange <oldpassphrase> <newpassphrase>\nChanges the wallet passphrase from <oldpassphrase> to <newpassphrase>." },
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: 2GiveCoin-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want POSIX (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: 2GiveCoin-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    const char *cStatus;
         if (nStatus == HTTP_OK) cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN) cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND) cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %"PRIszu"\r\n"
            "Content-Type: application/json\r\n"
            "Server: 2GiveCoin-json-rpc/%s\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time().c_str(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    while (true)
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return strUserPass == strRPCUserColonPass;
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST) nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());

	std::string ipv4addr = address.to_string();

    if (address == asio::ip::address_v4::loopback()
     || address == asio::ip::address_v6::loopback()
     || (address.is_v4()
         // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
        return true;

    const string strAddress = address.to_string();
    const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
    BOOST_FOREACH(string strAllow, vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(stream.get_io_service());
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    asio::ssl::stream<typename Protocol::socket>& stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(
            asio::io_service& io_service,
            ssl::context &context,
            bool fUseSSL) :
        sslStream(io_service, context),
        _d(sslStream, fUseSSL),
        _stream(_d)
    {
    }

    virtual std::iostream& stream()
    {
        return _stream;
    }

    virtual std::string peer_address_to_string() const
    {
        return peer.address().to_string();
    }

    virtual void close()
    {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    iostreams::stream< SSLIOStreamDevice<Protocol> > _stream;
};

void ThreadRPCServer(void* parg)
{
    // Make this thread recognisable as the RPC listener
    RenameThread("bitcoin-rpclist");

    try
    {
        vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[THREAD_RPCLISTENER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    printf("ThreadRPCServer exited\n");
}

// Forward declaration required for RPCListen
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                boost::asio::placeholders::error));
}

/**
 * Accept and handle incoming connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error)
{
    vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted
     && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

    // TODO: Actually handle errors
    if (error)
    {
        delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn
          && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    }

    // start HTTP client thread
    else if (!NewThread(ThreadRPCServer3, conn)) {
        printf("Failed to create RPC server client thread\n");
        delete conn;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
}

void ThreadRPCServer2(void* parg)
{
    printf("ThreadRPCServer started\n");

    strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    if (mapArgs["-rpcpassword"] == "")
    {
        unsigned char rand_pwd[32];
        RAND_bytes(rand_pwd, 32);
        string strWhatAmI = "To use 2GiveCoind";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
              "It is recommended you use the following random password:\n"
              "rpcuser=bitcoinrpc\n"
              "rpcpassword=%s\n"
              "(you do not need to remember this password)\n"
              "If the file does not exist, create it with owner-readable-only file permissions.\n"),
                strWhatAmI.c_str(),
                GetConfigFile().string().c_str(),
                EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32).c_str()),
            _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    const bool fUseSSL = GetBoolArg("-rpcssl");

    asio::io_service io_service;

    ssl::context context(io_service, ssl::context::sslv23);
    if (fUseSSL)
    {
        context.set_options(ssl::context::no_sslv2);

        filesystem::path pathCertFile(GetArg("-rpcsslcertificatechainfile", "server.cert"));
        if (!pathCertFile.is_complete()) pathCertFile = filesystem::path(GetDataDir()) / pathCertFile;
        if (filesystem::exists(pathCertFile)) context.use_certificate_chain_file(pathCertFile.string());
        else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());

        filesystem::path pathPKFile(GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (!pathPKFile.is_complete()) pathPKFile = filesystem::path(GetDataDir()) / pathPKFile;
        if (filesystem::exists(pathPKFile)) context.use_private_key_file(pathPKFile.string(), ssl::context::pem);
        else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());

        string strCiphers = GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
    }

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool loopback = !mapArgs.count("-rpcallowip");
    asio::ip::address bindAddress = loopback ? asio::ip::address_v6::loopback() : asio::ip::address_v6::any();
    ip::tcp::endpoint endpoint(bindAddress, GetArg("-rpcport", GetDefaultRPCPort()));
    boost::system::error_code v6_only_error;
    boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(io_service));

    boost::signals2::signal<void ()> StopRequests;

    bool fListening = false;
    std::string strerr;
    try
    {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(socket_base::max_connections);

        RPCListen(acceptor, context, fUseSSL);
        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRequests.connect(signals2::slot<void ()>(
                    static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                .track(acceptor));

        fListening = true;
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
    }

    try {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fListening || loopback || v6_only_error)
        {
            bindAddress = loopback ? asio::ip::address_v4::loopback() : asio::ip::address_v4::any();
            endpoint.address(bindAddress);

            acceptor.reset(new ip::tcp::acceptor(io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(socket_base::max_connections);

            RPCListen(acceptor, context, fUseSSL);
            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRequests.connect(signals2::slot<void ()>(
                        static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                    .track(acceptor));

            fListening = true;
        }
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv4: %s"), endpoint.port(), e.what());
    }

    if (!fListening) {
        uiInterface.ThreadSafeMessageBox(strerr, _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (!fShutdown)
        io_service.run_one();
    vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
}

class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

void JSONRequest::parse(const Value& valRequest)
{
    // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getwork" && strMethod != "getblocktemplate")
        printf("ThreadRPCServer method=%s\n", strMethod.c_str());

    // Parse params
    Value valParams = find_value(request, "params");
    if (valParams.type() == array_type)
        params = valParams.get_array();
    else if (valParams.type() == null_type)
        params = Array();
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
    }
    catch (Object& objError)
    {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

static CCriticalSection cs_THREAD_RPCHANDLER;

void ThreadRPCServer3(void* parg)
{
    // Make this thread recognisable as the RPC handler
    RenameThread("bitcoin-rpchand");

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]++;
    }
    AcceptedConnection *conn = (AcceptedConnection *) parg;

    bool fRun = true;
    while (true) {
        if (fShutdown || !fRun)
        {
            conn->close();
            delete conn;
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        map<string, string> mapHeaders;
        string strRequest;

        ReadHTTP(conn->stream(), mapHeaders, strRequest);

        // Check authorization
        if (mapHeaders.count("authorization") == 0)
        {
            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (!HTTPAuthorized(mapHeaders))
        {
            printf("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());
            /* Deter brute-forcing short passwords.
               If this results in a DOS the user really
               shouldn't have their RPC port exposed.*/
            if (mapArgs["-rpcpassword"].size() < 20)
                Sleep(250);

            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close")
            fRun = false;

        JSONRequest jreq;
        try
        {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest))
                throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

            string strReply;

            // singleton request
            if (valRequest.type() == obj_type) {
                jreq.parse(valRequest);

                Value result = tableRPC.execute(jreq.strMethod, jreq.params);

                // Send reply
                strReply = JSONRPCReply(result, Value::null, jreq.id);

            // array of requests
            } else if (valRequest.type() == array_type)
                strReply = JSONRPCExecBatch(valRequest.get_array());
            else
                throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

            conn->stream() << HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        }
        catch (Object& objError)
        {
            ErrorReply(conn->stream(), objError, jreq.id);
            break;
        }
        catch (std::exception& e)
        {
            ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
            break;
        }
    }

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]--;
    }
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params) const
{
    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode") &&
        !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try
    {
        // Execute
        Value result;
        {
            if (pcmd->unlocked)
                result = pcmd->actor(params, false);
            else {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    }
    catch (std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}


Object CallRPC(const string& strMethod, const Array& params)
{
    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
                GetConfigFile().string().c_str()));

    // Connect to localhost
    bool fUseSSL = GetBoolArg("-rpcssl");
    asio::io_service io_service;
    ssl::context context(io_service, ssl::context::sslv23);
    context.set_options(ssl::context::no_sslv2);
    asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
    SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
    iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);
    if (!d.connect(GetArg("-rpcconnect", "127.0.0.1"), GetArg("-rpcport", itostr(GetDefaultRPCPort()))))
        throw runtime_error("couldn't connect to server");

    // HTTP basic authentication
    string strUserPass64 = EncodeBase64(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string strReply;
    int nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}




template<typename T>
void ConvertTo(Value& value, bool fAllowNull=false)
{
    if (fAllowNull && value.type() == null_type)
        return;
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        string strJSON = value.get_str();
        if (!read_string(strJSON, value2))
            throw runtime_error(string("Error parsing JSON:")+strJSON);
        ConvertTo<T>(value2, fAllowNull);
        value = value2;
    }
    else
    {
        value = value.get_value<T>();
    }
}

// Convert strings to command-specific RPC representation
Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    Array params;
    BOOST_FOREACH(const std::string &param, strParams)
        params.push_back(param);

    int n = params.size();

    //
    // Special case non-string parameter types
    //
    if (strMethod == "stop"                   && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "setmint"                && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getbalance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "getblock"               && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockbynumber"       && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "getblockbynumber"       && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockhash"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);
    if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "sendfrom"               && n > 3) ConvertTo<boost::int64_t>(params[3]);
    if (strMethod == "listtransactions"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listtransactions"       && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "listaccounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "walletpassphrase"       && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "getblocktemplate"       && n > 0) ConvertTo<Object>(params[0]);
    if (strMethod == "listsinceblock"         && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "sendmany"               && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "sendmany"               && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "reservebalance"          && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "reservebalance"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "addmultisigaddress"     && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "listunspent"            && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listunspent"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listunspent"            && n > 2) ConvertTo<Array>(params[2]);
    if (strMethod == "getrawtransaction"      && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "createrawtransaction"   && n > 0) ConvertTo<Array>(params[0]);
    if (strMethod == "createrawtransaction"   && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "signrawtransaction"     && n > 1) ConvertTo<Array>(params[1], true);
    if (strMethod == "signrawtransaction"     && n > 2) ConvertTo<Array>(params[2], true);

    return params;
}

int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        Array params = RPCConvertValues(strMethod, strParams);

        // Execute
        Object reply = CallRPC(strMethod, params);

        // Parse reply
        const Value& result = find_value(reply, "result");
        const Value& error  = find_value(reply, "error");

        if (error.type() != null_type)
        {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet = abs(code);
        }
        else
        {
            // Result
            if (result.type() == null_type)
                strPrint = "";
            else if (result.type() == str_type)
                strPrint = result.get_str();
            else
                strPrint = write_string(result, true);
        }
    }
    catch (std::exception& e)
    {
        strPrint = string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}




#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            printf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    } catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif

const CRPCTable tableRPC;
