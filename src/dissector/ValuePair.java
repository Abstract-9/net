package dissector;


class ValuePair<L,R> {

    private final L left;
    private final R right;

    ValuePair(L left, R right){
        this.left = left;
        this.right = right;
    }

    L getKey(){
       return left;
    }

    R getValue(){
        return right;
    }


}
