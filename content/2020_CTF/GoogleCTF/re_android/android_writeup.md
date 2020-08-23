## Google CTF 2020: Android
> Can you find the correct key to unlock this app?
##### *tl;dr: a few minutes of reversing the algorithm, 5 hours for bruteforcing*

#### This challenge marked a lot of firsts for me as a CTF player: first time joining a team to compete with (OpenToAll) despite me being beginner-level at best and capturing a flag for them; first time I solved a main challenge from Google CTF (I assumed this was a non-beginner challenge since there were no beginner's quest challenges this year and this was not marked as easy in the challenge description). I had fun reversing, scripting a keygen for the challenge, and writing this writeup. For me, this is a milestone and one of the reasons for me to keep grinding, sharpening my skillset to be on par with the greatest players/teams in the world and hopefully be a decorated exploit developer in the near future.

### APK Static Analysis
#### Seeing that we were given an apk to reverse, my plan was to first decompile the apk with jadx-gui and have a peek at the source code. If there were interesting stuff that were referenced but not included in the result, I would then open the apk with apktool. The following 86 lines of code are what seems to be the MainActivity file for the application.
```java
package com.google.ctf.sandbox;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/* renamed from: com.google.ctf.sandbox.ő  reason: contains not printable characters */
public class C0000 extends Activity {

    /* renamed from: class  reason: not valid java name */
    long[] f0class;

    /* renamed from: ő  reason: contains not printable characters */
    int f1;

    /* renamed from: ő  reason: contains not printable characters and collision with other field name */
    long[] f2;

    public C0000() {
        try {
            this.f0class = new long[]{40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821};
            this.f2 = new long[12];
            this.f1 = 0;
        } catch (I unused) {
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final EditText editText = (EditText) findViewById(R.id.editText);
        final TextView textView = (TextView) findViewById(R.id.textView);
        ((Button) findViewById(R.id.button)).setOnClickListener(new View.OnClickListener() {
            /* class com.google.ctf.sandbox.C0000.AnonymousClass1 */

            public void onClick(View v) {
                C0000.this.f1 = 0;
                try {
                    StringBuilder keyString = new StringBuilder();
                    for (Object chr : new Object[]{65, 112, 112, 97, 114, 101, 110, 116, 108, 121, 32, 116, 104, 105, 115, 32, 105, 115, 32, 110, 111, 116, 32, 116, 104, 101, 32, 102, 108, 97, 103, 46, 32, 87, 104, 97, 116, 39, 115, 32, 103, 111, 105, 110, 103, 32, 111, 110, 63}) {
                        keyString.append(((Character) chr).charValue());
                    }
                    if (editText.getText().toString().equals(keyString.toString())) {
                        textView.setText("🚩");
                    } else {
                        textView.setText("❌");
                    }
                } catch (J | Error | Exception unused) {
                    String flagString = editText.getText().toString();
                    if (flagString.length() != 48) {
                        textView.setText("❌");
                        return;
                    }
                    for (int i = 0; i < flagString.length() / 4; i++) {
                        C0000.this.f2[i] = (long) (flagString.charAt((i * 4) + 3) << 24);
                        long[] jArr = C0000.this.f2;
                        jArr[i] = jArr[i] | ((long) (flagString.charAt((i * 4) + 2) << 16));
                        long[] jArr2 = C0000.this.f2;
                        jArr2[i] = jArr2[i] | ((long) (flagString.charAt((i * 4) + 1) << '\b'));
                        long[] jArr3 = C0000.this.f2;
                        jArr3[i] = jArr3[i] | ((long) flagString.charAt(i * 4));
                    }
                    C0000 r6 = C0000.this;
                    if (((R.m0(C0000.this.f2[C0000.this.f1], 4294967296L)[0] % 4294967296L) + 4294967296L) % 4294967296L != C0000.this.f0class[C0000.this.f1]) {
                        textView.setText("❌");
                        return;
                    }
                    C0000.this.f1++;
                    if (C0000.this.f1 >= C0000.this.f2.length) {
                        textView.setText("🚩");
                        return;
                    }
                    throw new RuntimeException();
                }
            }
        });
    }
}
```
#### Continue here...


