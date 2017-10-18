package scrooge;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class TxHandler {
    private UTXOPool pool;
    private TxValidator validator = new TxValidator();

    private class TxValidator {
        private double inSum = 0, outSum = 0;

        private boolean inputIsValid(UTXOPool pool, Transaction tx) {
            inSum = 0;
            Set<UTXO> usedTxs = new HashSet<>();

            for (int i = 0; i < tx.numInputs(); i++) {
                Transaction.Input input = tx.getInput(i);
                if (input == null) {
                    return false;
                }

                UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

                if (!pool.contains(utxo) || usedTxs.contains(utxo)) {
                    return false;
                }
                Transaction.Output prevTxOut = pool.getTxOutput(utxo);

                PublicKey pubKey = prevTxOut.address;
                byte[] message = tx.getRawDataToSign(i);
                byte[] signature = input.signature;
                if (!Crypto.verifySignature(pubKey, message, signature)) {
                    return false;
                }
                usedTxs.add(utxo);

                inSum += prevTxOut.value;
            }
            return true;
        }

        private boolean isNotNull(Transaction tx) {
            return tx != null;
        }

        private boolean outputIsValid(Transaction tx) {
            outSum = 0;
            for (int i = 0; i < tx.numOutputs(); i++) {
                Transaction.Output out = tx.getOutput(i);
                if (out.value < 0) {
                    return false;
                }
                outSum += out.value;
            }

            return inSum >= outSum;
        }

        public boolean validate(UTXOPool pool, Transaction tx) {
            return isNotNull(tx) && inputIsValid(pool, tx) && outputIsValid(tx);
        }
    }

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.pool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        return validator.validate(this.pool, tx);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        if (possibleTxs == null) {
            return new Transaction[0];
        }
        ConcurrentHashMap<byte[], Transaction> txs = getTxMap(possibleTxs);

        ArrayList<Transaction> valid = new ArrayList<>();
        int txCount;
        do {
            txCount = txs.size();
            for (Transaction tx : txs.values()) {
                if (!isValidTx(tx)) {
                    continue;
                }
                valid.add(tx);
                this.applyTx(tx);
                txs.remove(tx.getHash());
            }
            if (txCount == txs.size() || txCount == 0) { // still the same
                break; // nothing to check
            }
        } while (true);

        return valid.toArray(new Transaction[valid.size()]);
    }

    private void applyTx(Transaction tx) {
        if (tx == null) {
            return;
        }
        for (Transaction.Input input : tx.getInputs()) {
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            this.pool.removeUTXO(utxo);
        }
        byte[] txHash = tx.getHash();
        int index = 0;
        for (Transaction.Output output : tx.getOutputs()) {
            UTXO utxo = new UTXO(txHash, index);
            index += 1;
            this.pool.addUTXO(utxo, output);
        }
    }

    private ConcurrentHashMap<byte[], Transaction> getTxMap(Transaction[] possibleTxs) {
        ConcurrentHashMap<byte[], Transaction> txs = new ConcurrentHashMap<>();

        for (Transaction tx : possibleTxs) {
            if (tx == null) {
                continue;
            }
            // buffer the hashes so we don't have to re-calculate them later on
            tx.finalize();
            txs.put(tx.getHash(), tx);
        }
        return txs;
    }

}

