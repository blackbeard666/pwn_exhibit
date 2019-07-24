## peaCTF: Coffee Time
> Run this jar executable in a virtual machine and see what happens. coffeetime.jar

##### *tl;dr: basic reverse engineering/decompilation of a Java JAR file*
#### I've been away from the security scene for quite sometime, and this is the first CTF that I've joined since April. Having goals of becoming a Malware Analyst, I thought of learning more RE by focusing on this category during such challenges. 

## Analysis
#### Starting off, we are given a java .jar file which we are supposed to run in a vm as stated in the description, but we'll be doing it in our local machine anyways *absolute madlad*. Running the application takes a while and presents us a randomly generated number whose value raised to 10000 we need to compute while being given a very short amount of time to solve it. Even if we did write a short script to solve the problem, it would take a large amount of time to compute the result making the effort useless since we are under time pressure.

## Reversing
#### What I ended up doing was loading the application into [jadx](https://github.com/skylot/jadx), thus getting a decompiled version of it. Scanning through the subdirectories, we locate the main source file which houses the logic as well as the flag for the challenge.
##### CoffeeTime.java
```java
package coffeetime;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.TerminalBuilder;

public class CoffeeTime {
    public static void main(String[] args) throws Exception {
        new CoffeeTime();
    }

    public CoffeeTime() throws IOException, InterruptedException {
        LineReader lineReader = LineReaderBuilder.builder().terminal(TerminalBuilder.terminal()).build();
        if (lineReader.readLine("Can you give me some time to calculate a number? [y/n]\n").equals("y")) {
            BigInteger bigInteger = new BigInteger(2000, new Random());
            long timestart = System.currentTimeMillis();
            BigInteger result = bigInteger.pow(10000);
            long timeend = System.currentTimeMillis();
            int secs = (int) (((double) (timeend - timestart)) / 5.0d);
            System.out.println("\nWhat is " + bigInteger + " to the power of 10000?");
            System.out.println("You have " + (((double) secs) / 1000.0d) + " seconds to answer.");
            Thread.sleep((long) secs);
            String line = lineReader.readLine();
            System.out.println("\nPlease wait.");
            if (!line.equals(result.toString())) {
                System.out.println("Wrong answer, unfortunately.");
            } else if (System.currentTimeMillis() > ((long) secs) + timeend) {
                System.out.println("Uh-oh, time's out.");
            } else {
                System.out.println("peaCTF{nice_cup_of_coffee}");
            }
        }
    }
}
```
