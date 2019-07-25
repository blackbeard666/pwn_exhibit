## peaCTF: Coffee Time
> Run this jar executable in a virtual machine and see what happens. coffeetime.jar

##### *tl;dr: basic reverse engineering/decompilation of a Java JAR file*
#### I've been away from the security scene for quite sometime, and this is the first CTF that I've joined since April. Having goals of becoming a Malware Analyst, I thought of learning more RE by focusing on this category during such challenges. 

## Analysis
#### Starting off, we are given a java .jar file which we are supposed to run in a vm as stated in the description, but we'll be doing it in our local machine anyways *absolute madlad*. Running the application takes a while and presents us a randomly generated number whose value raised to 10000 we need to compute while being given a very short period of time to solve it. Even if we did write a short script to solve the problem, it would take a large amount of time to compute the result making the effort useless since we are under time pressure.
```
$ java -jar coffeetime.jar
Can you give me some time to calculate a number? [y/n]
y

What is 68311714374873809918774041263188460777771677317908469594061063155493156094971439145583741391495745304771548884514499419555452319487718337979922903799247102988859893378423567873852996493539120794550568492353434351114501481293212318723961164596472079133568236355339196500969859215667250664805821704652690504652872376844906930927214933160499124709402945367913172990873650580253650599177735603404973972976577996903673590310680442472884953906333516345903846351500704738772428549928708871037574743268623023678317330601801027399872538987771903167019708393039091031598623250621171431405602514357501149357240846 to the power of 10000?
You have 2.34 seconds to answer.
say sike right now

Please wait.
Wrong answer, unfortunately.
```

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
