pragma solidity >=0.8.1;
contract ABC {
    int256 private x;
    /// #if_succeeds {:msg "P1"} y == 30; 
    function ABCD() public view returns (int256 y) {
        if (x == 30) {
            assert(false);
            return 3;
        }
        if (x == 50) {
            assert(false);
            return 5;
        }
        if (x == 70) {
            assert(false);
            return 7;
        }
        if (x == 90) {
            assert(false);
            return 9;
        }
        if (x == 110) {
            assert(false);
            return 11;
        }
        if (x == 130) {
            assert(false);
            return 13;
        }
        if (x == 150) {
            assert(false);
            return 15;
        }
        if (x == 170) {
            assert(false);
            return 17;
        }
        if (x == 190) {
            assert(false);
            return 19;
        }
        if (x == 210) {
            assert(false);
            return 21;
        }
        if (x == 230) {
            assert(false);
            return 23;
        }
        if (x == 250) {
            assert(false);
            return 25;
        }
        return 0;
    }
    function SetNext(bool b) public {
        x = int256(2)*x + (b ? int256(1) : int256(0));
    }
}