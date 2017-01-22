package dissector;


public class ValuePair<L,R> {

    private final L left;
    private final R right;

    ValuePair(L key, R value){
        this.left = key;
        this.right = value;
    }

    public L getKey(){
       return left;
    }

    public R getValue(){
        return right;
    }


}
