/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package circuit.structure;

import java.math.BigInteger;

public class AffinePoint {
    public Wire x;
    public Wire y;

    public AffinePoint(Wire x) {
        this.x = x;
    }

    public AffinePoint(Wire x, Wire y) {
        this.x = x;
        this.y = y;
    }

    public AffinePoint(AffinePoint p) {
        this.x = p.x;
        this.y = p.y;
    }
}
