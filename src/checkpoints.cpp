// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2016 Strength In Numbers Foundation

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "db.h"
#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
/*dvd first checkpoints are PRIME candidates ;-)
      2      3      5      7     11     13     17     19     23     29
     31     37     41     43     47     53     59     61     67     71
     73     79     83     89     97    101    103    107    109    113
    127    131    137    139    149    151    157    163    167    173
    179    181    191    193    197    199    211    223    227    229
    233    239    241    251    257    263    269    271    277    281
    283    293    307    311    313    317    331    337    347    349
    353    359    367    373    379    383    389    397    401    409
    419    421    431    433    439    443    449    457    461    463
    467    479    487    491    499
*/
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
            (    0, hashGenesisBlockOfficial )
            (    2, uint256("0x00000a30710ef17b5db6ef891423341c526283a9021572420c578f69b50cb6ff"))
            (    3, uint256("0x00000579feaf9a49b59c9f6f5681829a027584914bb2384086d43f6bd34cfca6"))
            (    5, uint256("0x0000055a98f971cff970b97556f1fd1de255489ccdb2185244a00b827e25c4f9"))
            (    7, uint256("0x00000b2bafdb31171adc4844eff1a8c19dcb70b34f738a9155bc239168adda59"))
            (   11, uint256("0x00000ade45b55a0253fee8dbba55861f1ad2112fec4e1dd696dd667fabd5d15b"))
            (   13, uint256("0x000001211d3080ff700cfbcefb93e9c07e45dc37416dc751cc79d2aecde7e72c"))
            (   17, uint256("0x000001ecb5bf4733a18c120c5340832fde6479ab74d5b56b5511b8f060cc8a10"))
            (   19, uint256("0x000001e7cef7753b4c28e4c039fcec874818923bb814e02893b0ed778f0194c8"))
            (   23, uint256("0x00000d359135cc0675e6f2297066b15c34de3d7537bf9af0f4aa1c219f2e1054"))
            (   29, uint256("0x00000107998808c4581fa8dfb0c0ac317d10cfc02589da326b0d363cbbbdeadc"))
            (   31, uint256("0x000006f8154bf2114cb65bf0806d7022786cf10b86a4646a9bbb8fa32c259af2"))
            (   37, uint256("0x000002d2bc6547cec5d43add63f577794c4e427c3b09fb5f984c8294d4c68a84"))
            (   41, uint256("0x00000a4b032b04ad03e44fd905a68b6864a492a8f59e9231e0c345f4d9220e41"))
            (   43, uint256("0x000009382eb6db29e4e1ded4196af14d4de1906047298dc65c2153c0f97346b7"))
            (   47, uint256("0x0000044c63342a637ffc4132ba41b91d2b64163d47ceb698cbbc79e043517be7"))
            (   53, uint256("0x000005c8e59beb00b230a705e36a52f10a1d652f2060a2ede0ceed77af89c04a"))
            (   59, uint256("0x000001c17e07554025d2ab39a4058a3ae4cad722caf1100c0fb97e1b281e15d1"))
            (   61, uint256("0x000004ebc75b3cf4db0509e7d3fde6cc695a07c2477f3847e9ae5adcb718d630"))
            (   67, uint256("0x0000082dccb0f80e1b762c948d85a01fd1af997da8eaa4ff7d9f5c8da948089b"))
            (   71, uint256("0x00000a15076484a17bc51fc61620c01fb1edb548a64f68cd9c7a3cc1fccc1816"))
            (   73, uint256("0x000008481e26b714461775c46ad81bb3d882ff8e7b0abeaaad58a7701f0cc41a"))
            (   79, uint256("0x0000019c29385a4014576362d8043001d81d683edf35df8eb9c7bbe84df02c38"))
            (   83, uint256("0x000006491f0fe010b01ee622df584ada43c6de4e118a421d78237fd263ddb770"))
            (   89, uint256("0x000006e6ba7b54ddbba3dcd3d372632f413ae119144b8c5db563d4c0926684b7"))
            (   97, uint256("0x0000067c45c482fc26a5f6ffe7b62e637bac4bf6d959691e232e9441588b9f35"))
            (  101, uint256("0x0000065b0b21b2c7b89e1473f895ff7882135e1241c7566ceca84ad98c95142e"))
            (  103, uint256("0x0000046843f42ddb5e6ddb49af64836f758ebd2b77165524562898b70541e3b6"))
            (  107, uint256("0x0000076c469b2c9e545a207b9966cbdd5edb0f955eee8831d69903e0318fda3c"))
            (  109, uint256("0x0000093d9eea5e81eff655e491e19d23913b1674db26eefcc5e9bf65e45bbe51"))
            (  113, uint256("0x0000095ca0afa809a4d6b43ff4887b40636f605d8490c7e3e755e9d06d598d3c"))
            (  127, uint256("0x000006c04e5cde4b979d52084a23c066675be27b983693b4c7fb57f274619217"))
            (  131, uint256("0x00000477f13b258961c4af92fc4af26550f338edd6314e81b5bd9a1598f823fa"))
            (  137, uint256("0x000001d9349c10285696590ada58f33296978cf7eb2e5a62a98c620c01abe0b2"))
            (  139, uint256("0x000002b8a35a77022b15cd7ae8acb97518fa14b2aa3aa9a81a68464837746a6b"))
            (  149, uint256("0x000004f555269d0319d6d02c1d369faae079649c8521aae16c38d964e18bca95"))
            (  151, uint256("0x000002ffe979f13e49e130f6a53f9b615873e3286bd1b03df9aa17bbf2d1570e"))
            (  157, uint256("0x000001546186a9517fcc5f1f8dcabca2c56ad491daf312e5b03e5e24a6ed429b"))
            (  163, uint256("0x00000252841affcad5715b3626bb632ab25f2f3ac505ea726dc058c3eee32f36"))
            (  167, uint256("0x0000000924d56959ad612b210061e4e2513985f14f14b777956080579da78821"))
            (  173, uint256("0x000001c56dbb2652226ac608583c43579447aec18bbdcf59d20538375a1b6383"))
            (  179, uint256("0x000000bb27bc6948a05683dd473fc5bf52a5bb6fa4a4be713576842b62e72c9e"))
            (  181, uint256("0x0000061e9dbc6237321c8c0fd3ede81747a0bdc5bef4164f7235163f0924386c"))
            (  191, uint256("0x000000b49742874274e6551aa1e32105513a4c73b9c2e48f8aa1e8649570af45"))
            (  193, uint256("0x000003ee7cad709af3433e69813934eabb3882df84cd49f5548a71b0bc88da99"))
            (  197, uint256("0x000005353dcb6c9f4add5bb775935711ae73d02305a98866d72669ddf6ce2054"))
            (  199, uint256("0x000000f437ac58ce9abc6cb230b094c43b6be2795079e298f19ed32346aeaae5"))
            (  211, uint256("0x0000013ab592dac44bdab2b5e05b5c9dab87f287042cdb137bb13dc0dae958bf"))
            (  223, uint256("0x0000034f57befac5107f8488e0a43fafb55b2ef724f0b8c661c0bf25f4d832eb"))
            (  227, uint256("0x000007e222b8a35890081c77fd05b7bdf7fec19c9e53cba7e12d08cb8bfe45ae"))
            (  229, uint256("0x000002c97517e1be007a4d523b66c9a59dca74b7af9f9ecfb1ec8832c390d82c"))
            (  233, uint256("0x000001bdd8855ae36eeab78255688b561b72ff37bf22d9d9a3a30c51cbd15690"))
            (  239, uint256("0x000003eb70f306aa3ce6d370121f91d37cc753392a35200d957cc47cb887ec89"))
            (  241, uint256("0x000002889393b777ac467c8a24acf0c19eea5bbaa0b349b910b3923a47160f76"))
            (  251, uint256("0x000001db879031bfc8a4fdcf25941074cd393203af4b9b6dbfee3e2f01aea67c"))
            (  257, uint256("0x0000014b4c78fd3de479e87e441ff61262ad0c3f08cfa2eb42637d5864fd165b"))
            (  263, uint256("0x0000071f2e0bfe881a5f06b556f42f558b43f1d785e3bcec0dbb76893916f92c"))
            (  269, uint256("0x000004c0c46e71aaf48e342233f63ca987da759fd5eee68e42f54f722533b315"))
            (  271, uint256("0x0000056ce69771da60371dd2f24206a514720ace0bab7112454a38994e7f2b5e"))
            (  277, uint256("0x0000058be19d974f6cfee5324bd0eba9a89e1cfd4f66e070d58c1d2b640a25f8"))
            (  281, uint256("0x00000459ca1cabb8b609f927345d91a74bf3f262c3cc16f4a89dfa087cc4c842"))
            (  283, uint256("0x00000119b1e970d999e6d7b5e53d0c941ecc3ccc31a3fd870b5ef0008e786f04"))
            (  293, uint256("0x000001e87eadd31537fd8df6707e86d50b394c9d1c77805166489e5c63432ee4"))
            (  307, uint256("0x0000064661e422051aad25a94491f454aee497158f27f7c771cda500d5695f59"))
            (  311, uint256("0x0000032e333d78becc2983a9fbaffb82b1104b3c2f25313aa3f53ba720c364dd"))
            (  313, uint256("0x000000cce8f1e816590a337ea18705b67adc1818de67f56f57909808afc7437d"))
            (  317, uint256("0x0000036465e19c6e6e07da70aa05892ed69d95144d4902d1ce4c611e3b00c01f"))
            (  331, uint256("0x0000034fd0c82652d5b0595dd3287ace522ce3e6ee5d04200bb2ff430ecbddf3"))
            (  337, uint256("0x000005998603431d11653ea21d15c143d4b1228bb62eb0f59fe6e2021038805c"))
            (  347, uint256("0x000004afe0bca29b810d6393e806dc81f383b5380d5902c9c093fa37b21b31a7"))
            (  349, uint256("0x00000571d971c1859db18e18b71d7ce622cbca80e7ce2e02c8b8277fe67078e8"))
            (  353, uint256("0x00000631ba8df6e81a6b1b72b6e11bae27455ae81513f3f7bd884146458d70de"))
            (  359, uint256("0x00000478c9ff0e46723403f724b9ea46696dc759de3367eb8d5af1d60c297493"))
            (  367, uint256("0x000002acbc2d0c1dc03574addf9b2fd981e3688f9014140633bfd329c9b6b70c"))
            (  373, uint256("0x000004117ee904fae7fc346999405b1e13f44dc8cfb438a4f781577cb0828e83"))
            (  379, uint256("0x0000058869132915f1d4619fd68f641af4171c62a309a2a67133b53e492ab8ba"))
            (  383, uint256("0x000001de4d387b3229c1da15774bdfc97c861fec7b402e56dff99f5e98d7548d"))
            (  389, uint256("0x0000046267bb50035bafe7db71a185789c65ebbfe89552f99e956c2cae096f0c"))
            (  397, uint256("0x000004c8b605f80cab37170b912403582f1056580e6fcf2e7f2c75f520649802"))
            (  401, uint256("0x0000008040ca6c328715c896ef3daf82e1db9851abf83d40116ae93c570cf266"))
            (  409, uint256("0x000003fff579311e1b446eba6fdfbf2cf08995e08aadd3a7e8918dfd2fa5dcd0"))
            (  419, uint256("0x000002c627b71fe9b72ee05f3c6a7700c34eb787597424206bea9c19d216f295"))
            (  421, uint256("0x0000032c7275f203af4e6e5f272bedecb376f3406e72c5cd351761c799e9f9f0"))
            (  431, uint256("0x00000027ebb3b2aa8cacd9cfa7f4ab8183ca0b6f8c128965675c3f78496b4e2f"))
            (  433, uint256("0x000001988a924e43289354495180050b8a95e36e3cef39fe473c79453d8e5f78"))
            (  439, uint256("0x00000211b3d3977efe213da85c9ff57d173d7e47842ee0587f5ade3fff527f98"))
            (  443, uint256("0x000000b3f405adb743f237b5e537cec30617b8f26f84ca6d07746c3f6acbea71"))
            (  449, uint256("0x0000027f52e432976564490b70d64d17a942fa309fb821b6d16f1db2b0763624"))
            (  457, uint256("0x000001c1ab41324da5b87d7e41d0508b66c269ed006eeccd70a680e1fe1fd1ce"))
            (  461, uint256("0x00000034895c19ffbfcf509f4193dd6ac03793c15e84b9cab45bbcb045f2d7ac"))
            (  463, uint256("0x000003fee80fb843ef88d5a9404e586643f7cd10c30bb99f5d7f3c4fdc8c72da"))
            (  467, uint256("0x0000009da19057cff1f18e6c29e088ff2a31abde4a82238e5e7b5882fc58f488"))
            (  479, uint256("0x0000017722dc9a78e7cae7385f9acfd0ddfe1d7bd5866cb8fccfa5f8b0860a7b"))
            (  487, uint256("0x00000031927f949d87b0de071001639f307de172839ca71d1b99af93954b1a16"))
            (  491, uint256("0x0000004b39c7f72d28898d6bbde9f7cbfb82f4f837d364125b2a1bc5819ee0a3"))
            (  499, uint256("0x000002b56ab0f31fc818a2b34c425d97389b1b1441d1a5e002be40bd27bffafa"))
            (  500, uint256("0x000000590dece9bedea7d29a273ea9f66fe6d3c9592d5a4bafc9613b62cdc3ec"))  // not PRIME but last initial POW
            (  547, uint256("0x0000014eb752b324a0cce438dcaa187ae447ea7bdd1b55a29d331776b29f8141"))
            (  607, uint256("0x000003305038a6d72514de684f38a9f55d157b4e0ac5fb1fec58770d125904f2"))
            (  661, uint256("0x0000088efb44d093acaa412e210abd820884b3b6967f031fcf7918210b36c24e"))
            (  739, uint256("0x000001ae180ca5de28d784802fb91a73131107dba83326128160875f195f5848"))
            (  811, uint256("0x00000f6acc3bd6dd97af8a8c5e2b32a75c7bfe2694cda93ab076a9c0e25e588e"))
            (  877, uint256("0x0000000e11839925a892fa2fe45b79abc02157af360d1605a1cf2d90cad75a1d"))
            (  947, uint256("0x000007b17a97f7b426655949ff64757b746a9309553321f60c2d03c87d478150"))
            ( 1019, uint256("0x0000019e6c948a860ad8cebcdd3e546ea7505d55ee56233c5e3b2a7418ca7b83"))
            ( 1087, uint256("0x0000041888440fd0a9ae9666464fb6f9413c16f5f467afa186acc3667eeaebe7"))
            ( 1153, uint256("0x00000b9da7da607264e35a00b79d3bf02341f8cc7409604ef502ad45fcb055af"))
            ( 1229, uint256("0x00000918fa043b0890d4ee317185d589ff56c70b03b7fef239c6c77bc3d47b23"))
            ( 1297, uint256("0x00000317781d4fe202daa0a8519189bcf92fe32744d4d31290930ba2ca970dec"))
            ( 49208, uint256("0x000003e1c27946ac57fde950bfde6fa890f8c132824770eff1e26724b940cbe1"))
        ;


    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        (     0, hashGenesisBlockOfficial )
        ;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }
/* dvd tbd
    //! Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks) {
        if (pindex==NULL)
            return 0.0;

        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Params().Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->GetBlockTime())/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }
*/
    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // ppcoin: synchronized checkpoint (centrally broadcasted)
    uint256 hashSyncCheckpoint = 0;
    uint256 hashPendingCheckpoint = 0;
    CSyncCheckpoint checkpointMessage;
    CSyncCheckpoint checkpointMessagePending;
    uint256 hashInvalidCheckpoint = 0;
    CCriticalSection cs_hashSyncCheckpoint;

    // ppcoin: get last synchronized checkpoint
    CBlockIndex* GetLastSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        else
            return mapBlockIndex[hashSyncCheckpoint];
        return NULL;
    }

    // ppcoin: only descendant of current sync-checkpoint is allowed
    bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
    {
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        if (!mapBlockIndex.count(hashCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());

        CBlockIndex* pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        CBlockIndex* pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];

        if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
        {
            // Received an older checkpoint, trace back from current checkpoint
            // to the same height of the received checkpoint to verify
            // that current checkpoint should be a descendant block
            CBlockIndex* pindex = pindexSyncCheckpoint;
            while (pindex->nHeight > pindexCheckpointRecv->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
            if (pindex->GetBlockHash() != hashCheckpoint)
            {
                hashInvalidCheckpoint = hashCheckpoint;
                return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
            }
            return false; // ignore older checkpoint
        }

        // Received checkpoint should be a descendant block of the current
        // checkpoint. Trace back to the same height of current checkpoint
        // to verify.
        CBlockIndex* pindex = pindexCheckpointRecv;
        while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        if (pindex->GetBlockHash() != hashSyncCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        return true;
    }

    bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
    {
        CTxDB txdb;
        txdb.TxnBegin();
        if (!txdb.WriteSyncCheckpoint(hashCheckpoint))
        {
            txdb.TxnAbort();
            return error("WriteSyncCheckpoint(): failed to write to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
        if (!txdb.TxnCommit())
            return error("WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
        txdb.Close();

        Checkpoints::hashSyncCheckpoint = hashCheckpoint;
        return true;
    }

    bool AcceptPendingSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint))
        {
            if (!ValidateSyncCheckpoint(hashPendingCheckpoint))
            {
                hashPendingCheckpoint = 0;
                checkpointMessagePending.SetNull();
                return false;
            }

            CTxDB txdb;
            CBlockIndex* pindexCheckpoint = mapBlockIndex[hashPendingCheckpoint];
            if (!pindexCheckpoint->IsInMainChain())
            {
                CBlock block;
                if (!block.ReadFromDisk(pindexCheckpoint))
                    return error("AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                if (!block.SetBestChain(txdb, pindexCheckpoint))
                {
                    hashInvalidCheckpoint = hashPendingCheckpoint;
                    return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                }
            }
            txdb.Close();

            if (!WriteSyncCheckpoint(hashPendingCheckpoint))
                return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
            hashPendingCheckpoint = 0;
            checkpointMessage = checkpointMessagePending;
            checkpointMessagePending.SetNull();
            printf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", hashSyncCheckpoint.ToString().c_str());
            // relay the checkpoint
            if (!checkpointMessage.IsNull())
            {
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpointMessage.RelayTo(pnode);
            }
            return true;
        }
        return false;
    }

    // Automatically select a suitable sync-checkpoint 
    uint256 AutoSelectSyncCheckpoint()
    {
        // Proof-of-work blocks are immediately checkpointed
        // to defend against 51% attack which rejects other miners block 

        // Select the last proof-of-work block
        const CBlockIndex *pindex = GetLastBlockIndex(pindexBest, false);
        // Search forward for a block within max span and maturity window
        while (pindex->pnext && (pindex->GetBlockTime() + CHECKPOINT_MAX_SPAN <= pindexBest->GetBlockTime() || pindex->nHeight + std::min(6, nCoinbaseMaturity - 20) <= pindexBest->nHeight))
            pindex = pindex->pnext;
        return pindex->GetBlockHash();
    }

    // Check against synchronized checkpoint
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev)
    {
        if (fTestNet) return true; // Testnet has no checkpoints
        int nHeight = pindexPrev->nHeight + 1;

        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];

        if (nHeight > pindexSync->nHeight)
        {
            // trace back to same height as sync-checkpoint
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->nHeight > pindexSync->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("CheckSync: pprev null - block index structure failure");
            if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
                return false; // only descendant of sync-checkpoint can pass check
        }
        if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
            return false; // same height with sync-checkpoint
        if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
            return false; // lower height than sync-checkpoint
        return true;
    }

    bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint == 0)
            return false;
        if (hashBlock == hashPendingCheckpoint)
            return true;
        if (mapOrphanBlocks.count(hashPendingCheckpoint) 
            && hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
            return true;
        return false;
    }

    // ppcoin: reset synchronized checkpoint to last hardened checkpoint
    bool ResetSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        const uint256& hash = mapCheckpoints.rbegin()->second;
        if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain())
        {
            // checkpoint block accepted but not yet in main chain
            printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
            CTxDB txdb;
            CBlock block;
            if (!block.ReadFromDisk(mapBlockIndex[hash]))
                return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
            if (!block.SetBestChain(txdb, mapBlockIndex[hash]))
            {
                return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
            }
            txdb.Close();
        }
        else if(!mapBlockIndex.count(hash))
        {
            // checkpoint block not yet accepted
            hashPendingCheckpoint = hash;
            checkpointMessagePending.SetNull();
            printf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n", hashPendingCheckpoint.ToString().c_str());
        }

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
        {
            const uint256& hash = i.second;
            if (mapBlockIndex.count(hash) && mapBlockIndex[hash]->IsInMainChain())
            {
                if (!WriteSyncCheckpoint(hash))
                    return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
                printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
                return true;
            }
        }

        return false;
    }

    void AskForPendingSyncCheckpoint(CNode* pfrom)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocks.count(hashPendingCheckpoint)))
            pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
    }

    bool SetCheckpointPrivKey(std::string strPrivKey)
    {
        // Test signing a sync-checkpoint with genesis block
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = !fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        std::vector<unsigned char> vchPrivKey = ParseHex(strPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return false;

        // Test signing successful, proceed
        CSyncCheckpoint::strMasterPrivKey = strPrivKey;
        return true;
    }

    bool SendSyncCheckpoint(uint256 hashCheckpoint)
    {
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = hashCheckpoint;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        if (CSyncCheckpoint::strMasterPrivKey.empty())
            return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
        std::vector<unsigned char> vchPrivKey = ParseHex(CSyncCheckpoint::strMasterPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

        if(!checkpoint.ProcessSyncCheckpoint(NULL))
        {
            printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
            return false;
        }

        // Relay checkpoint
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
        return true;
    }

    // Is the sync-checkpoint outside maturity window?
    bool IsMatureSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (nBestHeight >= pindexSync->nHeight + nCoinbaseMaturity ||
                pindexSync->GetBlockTime() + nStakeMinAge < GetAdjustedTime());
    }

    // Is the sync-checkpoint too old?
    bool IsSyncCheckpointTooOld(unsigned int nSeconds)
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
    }
}

//dvd tbd
// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "04af5bbbc222d254ad59ea0cb9debb33c000f054505016bfc7e5dca8df905d6846a4c484a83c0157dd662064dc0ee45b43abc14af4056d93ad482235058a2d4a57";

std::string CSyncCheckpoint::strMasterPrivKey = "";

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    CKey key;
    if (!key.SetPubKey(ParseHex(CSyncCheckpoint::strMasterPubKey)))
        return error("CSyncCheckpoint::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// ppcoin: process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)? WantedByOrphan(mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!Checkpoints::ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CTxDB txdb;
    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (!pindexCheckpoint->IsInMainChain())
    {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!block.ReadFromDisk(pindexCheckpoint))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        if (!block.SetBestChain(txdb, pindexCheckpoint))
        {
            Checkpoints::hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }
    txdb.Close();

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
