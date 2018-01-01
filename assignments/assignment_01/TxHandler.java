import java.util.ArrayList;
import java.security.PublicKey;
import java.util.HashSet;
import java.security.interfaces.RSAKey;


public class TxHandler {

    private UTXOPool upool;

    public TxHandler(UTXOPool utxoPool) {
        upool = new UTXOPool(utxoPool);
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

       // Get started
       //System.out.println( "Processing transaction " + tx);

 
       // Get the number of inputs and outputs
       //System.out.println( " Number of inputs: " + tx.numInputs());
       //System.out.println( " Number of outputs: " + tx.numOutputs());

       double sum_input = 0;
       double sum_output = 0;
       HashSet<UTXO> utxo = new HashSet<UTXO>();


       // Loop over the inputs
       for ( int i = 0; i < tx.numInputs(); i++) {

          // Get the input
          Transaction.Input txinput;
          txinput = tx.getInput(i);
          //System.out.println( " First input: " + txinput);
          
          // Get the corresponding output
          UTXO ut = new UTXO(txinput.prevTxHash, txinput.outputIndex);
          // If double, fail
          if (!utxo.add(ut)) return false;

          Transaction.Output txoutput  = upool.getTxOutput(ut); 

          // Check for null
          if (txoutput == null) return false;
          //System.out.println( " Corresponding output: " + txoutput);          

          // Get signature
          byte[] sign = tx.getRawDataToSign(i);
          //System.out.println( " Corresponding signature: " + sign);                    
    
          // Get message
          double value = txoutput.value;
          //System.out.println( " Value to be transferred: " + value);          

          // Get public key
          PublicKey address = txoutput.address;  
          //System.out.println( " Public Key or the address of the recipient: " + address);          
           
          // Verify
          Crypto cr = new Crypto();
          boolean verify = cr.verifySignature(address, sign, txinput.signature);
          if (verify) sum_input += txoutput.value;
          else return verify;
       }

       ArrayList<Transaction.Output> txOutputs = tx.getOutputs();
       for ( Transaction.Output op : txOutputs ) {
               if ( op.value < 0 ) return false;
               sum_output += op.value;
       }

       return ( sum_input >= sum_output);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */


   private boolean inPool(Transaction tx) {
      ArrayList<Transaction.Input> inputs = tx.getInputs();
      Transaction.Input txinput;
      UTXO ut;
      for (int i = 0; i < inputs.size(); i++) {
         txinput = inputs.get(i);
         ut = new UTXO(txinput.prevTxHash, txinput.outputIndex);
         if (!upool.contains(ut))
            return false;
      }
      return true;
   }

   private void updatePool(Transaction tx) {
      for (int i = 0; i < tx.getInputs().size(); i++) {
         Transaction.Input txinput = tx.getInput(i);
         upool.removeUTXO(new UTXO(txinput.prevTxHash, txinput.outputIndex));
      }
      for (int i = 0; i < tx.getOutputs().size(); i++) {
         Transaction.Output out = tx.getOutput(i);
         upool.addUTXO(new UTXO(tx.getHash(), i), out);
      }
   }


   public Transaction[] handleTxs(Transaction[] possibleTxs) {
      Transaction[] stuckTxs = new Transaction[possibleTxs.length];
      for (int i = 0; i < possibleTxs.length; i++)
         stuckTxs[i] = possibleTxs[i];
      Transaction[] tempTxs = new Transaction[possibleTxs.length];
      Transaction[] successTxs = new Transaction[possibleTxs.length];
      int tempCounter = 0, successCounter = 0;
      int stuckSize = possibleTxs.length;
      while (true) {
         boolean change = false;
         tempCounter = 0;
         for (int i = 0; i < stuckSize; i++) {
            if (inPool(stuckTxs[i])) {
               if (isValidTx(stuckTxs[i])) {
                  change = true;
                  updatePool(stuckTxs[i]);
                  successTxs[successCounter++] = stuckTxs[i];
               } // 1 if
            } // 2 if
            else tempTxs[tempCounter++] = stuckTxs[i];
         } // for 

         if (change) {
            for (int i = 0; i < tempCounter; i++)  
               stuckTxs[i] = tempTxs[i];
            stuckSize = tempCounter;
         } else break;

      } // while

      Transaction[] result = new Transaction[successCounter];
      for (int i = 0; i < successCounter; i++)
         result[i] = successTxs[i];
      return result;
   }



}
