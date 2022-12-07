/*
Need to be compiled with java7

javac TestUSMAgent.java
jar cvmf META-INF/MANIFEST.MF USMAgent.jar TestUSMAgent.class
 */

import java.lang.instrument.Instrumentation;

public class TestUSMAgent {

    public static void agentmain(String agentArgs, Instrumentation inst) {
        System.out.println("loading TestUSMAgent.agentmain("+agentArgs+")");
    }
    
}
