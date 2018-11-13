package rexec;

/*
 * @c, Apr-15, v1.0
 * Rexec

 * compile/run : 
	java -cp ".:jsch-0.1.52.jar:log4j-1.2.17.jar:commons-cli-1.3.1.jar" Rexec 
		-r <rhost file> 
		-u <user-passwd file> 
		-s <script file> 
		-t <script execution timeout in seconds/optional>
		-p <number of threads to process remote hosts in parallel>
		-o <optional arguments, to be passed to script file specified with -s option>

	javac -cp ".:jsch-0.1.52.jar:log4j-1.2.17.jar:commons-cli-1.3.1.jar" Rexec.java
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class Rexec {

	static final Logger log = Logger.getLogger(Rexec.class);

	public static void main(String[] args) {

		//BasicConfigurator.configure();
		if (new File("log4j.properties").canRead())
			PropertyConfigurator.configure("log4j.properties");

		ArrayList<String> rhosts = null;
		ArrayList<String> loginInfo = null;

		File hostFile = null;
		File upwdFile = null;
		File scriptFile = null;

		// default timeout, maxthreads value
		int scriptTimeout = 60;
		int maxThreads = 4;

		String scriptOptionalArgs = null;

		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();

		Options options = new Options();
		options.addOption(Option.builder("r").required(true).hasArg().argName("rhosts_file").desc("remote hosts list file, newline delimited.").build());
		options.addOption(Option.builder("u").required(true).hasArg().argName("user-passwd_file").desc("user credentials file.").build());
		options.addOption(Option.builder("s").required(true).hasArg().argName("script_file").desc("script file to be executed at remote host.").build());
		options.addOption(Option.builder("t").required(false).hasArg().argName("script_timeout").desc("script execution timeout at remote host, default 60s.").build());
		options.addOption(Option.builder("p").required(false).hasArg().argName("parallel_threads").desc("number of threads to process remote hosts in parallel, default 4.").build());
		options.addOption(Option.builder("o").required(false).hasArgs().argName("optional_args").desc("arguments that will be passed to script file.").build());

		try {
			CommandLine cmd = parser.parse( options, args);

			if (cmd.hasOption("r")) {
				hostFile = new File(cmd.getOptionValue("r"));
				if ( ! hostFile.canRead() ) {
					System.err.println("ERR_FILE_READ: unable to read file " + cmd.getOptionValue("r"));
					System.exit(1);
				}					
			} else {
				formatter.printHelp("Rexec", options);
				System.exit(1);					
			}

			if (cmd.hasOption("u")) {
				upwdFile = new File(cmd.getOptionValue("u"));
				if ( ! upwdFile.canRead() ) {
					System.err.println("ERR_FILE_READ: unable to read file " + cmd.getOptionValue("u"));
					System.exit(1);
				}					
			} else {
				formatter.printHelp("Rexec", options);
				System.exit(1);					
			}

			if (cmd.hasOption("s")) {
				scriptFile = new File(cmd.getOptionValue("s"));
				if ( ! scriptFile.canRead() ) {
					System.err.println("ERR_FILE_READ: unable to read file " + cmd.getOptionValue("s"));
					System.exit(1);
				}
			} else {
				formatter.printHelp("Rexec", options);
				System.exit(1);					
			}

			if (cmd.hasOption("t")) {
				scriptTimeout = Integer.parseInt(cmd.getOptionValue("t"));
			}

			if (cmd.hasOption("p")) {
				maxThreads = Integer.parseInt(cmd.getOptionValue("p"));
			}								

			if (cmd.hasOption("o")) {
				scriptOptionalArgs = cmd.getOptionValue("o");
			}				

		} catch (ParseException e) {
			System.err.println(e.getMessage());
			formatter.printHelp("Rexec", options);
			System.exit(1);
		}

		// read hosts file, upwd file and populate respective arrays

		try {
			rhosts = Rexec.fileContentToArrayList(hostFile);
			loginInfo = Rexec.fileContentToArrayList(upwdFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		UserInfo ui = new UserInfo();
		ui.setUser(loginInfo.get(0));
		ui.setPasswd(loginInfo.get(1));
		if (loginInfo.size() == 3 ) {
			ui.setSudoer(loginInfo.get(2));
		} else {
			ui.setSudoer(null);
		}
		ui.setScriptFile(scriptFile);
		ui.setMaxThreads(maxThreads);
		ui.setTimeout(scriptTimeout);
		ui.setOptionArgs(scriptOptionalArgs);

		log.debug("user : " + ui.getUser() + ", script_file : " + ui.getScriptFile().getName()
				+ ", max_threads : " + ui.getMaxThreads() + ",script_timeout : " + ui.getTimeout() 
				+ ", script_optional_args: " + ui.getOptionArgs());

		System.err.println(System.getProperty("line.separator") 
				+ "====Rexec program, run at " 
				+ new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) 
				+ "====" + System.getProperty("line.separator"));

		Rexec rExec = new Rexec(ui, rhosts);
		rExec.createThread();
		rExec.joinThreads();
		//System.out.println(rExec.getOut());
		System.out.println(rExec.getOutAsPerlHashStruct());
		System.exit(0);
	}

	private static ArrayList<String> rhosts;
	private static ArrayList<Thread> threads = new ArrayList<Thread>();
	private static ArrayList<String> out = new ArrayList<String>();

	private UserInfo ui;

	public Rexec(UserInfo ui, ArrayList<String> rhosts) {
		this.ui = ui;
		Rexec.rhosts = rhosts;
	}

	public void createThread() {
		System.err.println(System.getProperty("line.separator") 
				+ "====INFO: num# unique hosts " 
				+ Rexec.rhosts.size() 
				+ "====" 
				+ System.getProperty("line.separator"));
		for ( int i =0; i<Rexec.rhosts.size(); i++ ) {
			waitNumThreadBelowMax();
			Thread t = new Thread( this.new ThreadFactory(ui, Rexec.rhosts.get(i)) );
			Rexec.threads.add(t);
			t.start();
		}
		/*
			try {
					t.join();
			} catch ( InterruptedException e ) {
					e.printStackTrace();
			}
		 */
	}

	public static ArrayList<String> fileContentToArrayList(File file)
	throws FileNotFoundException, IOException {
		String str, tstr;
		ArrayList<String> list = new ArrayList<String>();
		BufferedReader in = new BufferedReader(new FileReader(file));
		Pattern commentRegex = Pattern.compile("^(#|$)");

		while ((str = in.readLine()) != null) {
			tstr = str.trim();
			Matcher commentMatcher = commentRegex.matcher(tstr);
			if ( ! commentMatcher.find()) {
				if ( ! list.contains(tstr) )
					list.add(tstr);
			}
		}
		in.close();
		return list;
	}

	public static class UserInfo {
		private String user, passwd, sudoer, optionArgs;
		private File scriptFile;
		private int	timeout, maxThreads; 

		public void setUser( String user ) {
			this.user = user;
		}

		public void setPasswd( String passwd ) {
			this.passwd = passwd;
		}

		public void setScriptFile( File scriptFile ) {
			this.scriptFile = scriptFile;
		}

		public void setSudoer( String sudoer ) {
			this.sudoer = sudoer;
		}		

		public void setTimeout( int timeout ) {
			this.timeout = timeout;
		}

		public void setMaxThreads( int maxThreads ) {
			this.maxThreads = maxThreads;
		}			

		public void setOptionArgs( String optionArgs ) {
			if ( optionArgs != null ) {
				this.optionArgs = optionArgs;
			} else {
				this.optionArgs = "";
			}
		}			

		public String getUser() {
			return user;
		}					

		public String getPasswd() {
			return passwd;
		}										

		public File getScriptFile() {
			return scriptFile;
		}	

		public String getSudoer() {
			return sudoer;
		}						

		public int getTimeout() {
			return timeout;
		}									

		public int getMaxThreads() {
			return maxThreads;
		}			

		public String getOptionArgs() {
			return optionArgs;
		}									
	}

	private class ThreadFactory implements Runnable {

		private UserInfo ui;
		private String rhost;

		public ThreadFactory(UserInfo ui, String rhost) {
			this.ui = ui;
			this.rhost = rhost;
		}

		private void cleanup(Expect x, Session session, ChannelSftp sftp) {
			if ( x != null ) {
				//x.send("exit\n");
				//x.expectEOF();
				x.close();
			}
			if ( sftp != null ) {
				sftp.disconnect();					
			}
			if ( session != null ) {
				session.disconnect();
			}				
		}

		public void run() {
			/*
						try {
								Expect.addLogToFile("expect.log",Level.DEBUG);
						} catch (IOException e) {
								System.err.println("IO error");
						}
			 */

			if ( log.isDebugEnabled() ) {
				Expect.addLogToConsole(Level.DEBUG);
			}

			log.debug("host: " + rhost + " run thread");

			JSch jsch = new JSch();
			Session session = null;
			Expect x = null;
			ChannelSftp c1 = null;
			Channel c2 = null;
			String remoteFileName = null;

			//Pattern promptLogon = Pattern.compile("(%|#|\\$)\\s*$");
			Pattern promptLogon = Pattern.compile("(%|>|\\$|\\])\\s*$");

			// negative lookbehind - not preceded by a '
			// to avoid match the cmd itself
			Pattern changedPS1 = Pattern.compile("(?<!')P-\\$\\s+$");
			Pattern promptPasswd = Pattern.compile("(?<!')cuStom-paSSwd: $");

			try {
				//JSch jsch = new JSch();
				log.debug("session obj, user: " + ui.getUser() + " host: " + rhost);
				session = jsch.getSession(ui.getUser(), rhost);
				session.setPassword(ui.getPasswd());
				session.setConfig("StrictHostKeyChecking", "no");
				session.connect(10 * 1000); // connection timeout
				c1 = (ChannelSftp)session.openChannel("sftp");;
				c1.connect();
				c1.cd("/tmp");

				//random name - script will be xfer'd as this name
				String randomName = "_" + new Random().nextInt(1000) + "_" + ui.getScriptFile().getName();

				//xfer file
				c1.put(new FileInputStream(ui.getScriptFile()), randomName);

				remoteFileName = c1.realpath(randomName);
				log.debug("remote file : " + remoteFileName);

				//c1.disconnect();

				c2 = session.openChannel("shell");
				x = new Expect(c2.getInputStream(), c2.getOutputStream());
				x.setDefault_timeout(ui.getTimeout());
				c2.connect();

				log.debug(promptLogon);
				// expect promptLogon for log on
				x.expectOrThrow(promptLogon);
				log.debug("prompt match ->" + x.match + "<-");

				// set PS1 env variable to string 'P-$ ' <-- for this PROMPT expect will wait -->
				// chmod execute perm to code file
				x.send("export PS1='P-$ '" + ";" + "chmod u+x,o+rx " + remoteFileName + "\n");
				x.expect(changedPS1);
				log.debug("prompt match (chmod executed) ->" + x.match + "<-");

				// execute code/script file
				if ( ui.getSudoer() != null ) {
					/*
									"sudo -k -u user -S -p 'cuStom-paSSwd: ' script args"
									OR
									"sudo -k -S -p 'cuStom-paSSwd: '  su  user -c 'script args'" // implemented 
					 */	

					/*	
									log.debug("sudo cmd ->" + "sudo -k -u " + ui.getSudoer() + " -S -p 'cuStom-paSSwd: ' " + remoteFileName + " " + ui.getOptionArgs() + "\n");
									x.send("sudo -k -u " + ui.getSudoer() + " -S -p 'cuStom-paSSwd: ' " + remoteFileName + " " + ui.getOptionArgs() + "\n");
					 */								
					log.debug("sudo cmd ->" + "sudo -k -S -p 'cuStom-paSSwd: ' su " + ui.getSudoer() + " -c '" + remoteFileName + " " + ui.getOptionArgs() + "'\n");
					x.send("sudo -k -S -p 'cuStom-paSSwd: ' su " + ui.getSudoer() + " -c '" + remoteFileName + " " + ui.getOptionArgs() + "'\n");
					/*
									the -k (kill) option to sudo invalidates the user’s timestamp by setting the time on it to the Epoch.  
									The next time sudo is run a	password will be required.

									Bug: On some hosts, sudo doesn't asks for password. 
										To handle this, program only expects for password prompt i.e. without raising exception.
										In case of success only password is sent.									
					 */
					x.expect(promptPasswd);
					if (x.isSuccess)
						x.send(ui.getPasswd() + "\n");
				} else {
					x.send(remoteFileName + " " + ui.getOptionArgs() + "\n");
				}

				// wait for script timeout
				x.expectOrThrow(ui.getTimeout(), changedPS1);
				log.debug("prompt match (code/script executed) ->" + x.match + "<-");
				log.debug("before prompt match "+ x.before);

				// match for output with in {}
				Matcher m = Pattern.compile("(?s)(?m)\\{.+\\}").matcher(x.before);
				if ( m.find() ) {
					//System.out.println(m.group());
					Rexec.out.add( rhost +  " => " + (String) m.group());
				} else {
					System.err.println("ERR_RHOST_UNSTRUCT: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost + " - " + x.before);
				}

				c1.rm(remoteFileName);

			} catch (JSchException e) {
				System.err.println("JSchException: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost + " - " + e.getMessage());
			} catch (IOException e) {
				System.err.println("IOException: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost + " - " + e.getMessage());
			} catch (SftpException e) {
				System.err.println("SftpException: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost + " - " + e.getMessage());
			} catch (Expect.TimeoutException e) {
				System.err.println("ExpectTimeoutException: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost  + " - " + e.getMessage());
			} catch (Expect.EOFException e) {
				System.err.println("ExpectEOFException: " + new SimpleDateFormat("yyyy.MM.dd'_'hh:mm:ss").format(new Date()) + " " + rhost  + " - " + e.getMessage());
			} finally {
				cleanup(x, session, c1);
			}

			/*
						String scpCmd, sshCmd;
						boolean scpSuccess = false;
						scpCmd = "/bin/scp -p -C -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
								+ code + " " + user + "@" + rhost + ":/tmp/" ;
						sshCmd = "/bin/ssh -n -q -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
								+ rhost + ":/tmp/" + code;


						Expect x1 = Expect.spawn(scpCmd);
						if ( expectOrThrow(x1,Pattern.compile(".*word\\s*:\\s*")) ) {
								x1.send(passwd);
								x1.expect(Pattern.compile("(?s)(?m).+"));
								if( x1.isSuccess ) {
										System.out.println(x1.match);
										scpSuccess = true;
								}
						}
						x1.close();

						if ( scpSuccess ) {
								Expect x2 = Expect.spawn(sshCmd);
								if ( expectOrThrow(x2,Pattern.compile(".*word\\s*:\\s*")) ) {
										x2.send(passwd);
										x2.expect(Pattern.compile("(?s)(?m).+"));
										System.out.println(" match : " + x2.match );
										Matcher m = Pattern.compile("(?s)(?m){.+}").matcher(x2.match);
										if ( m.find() ) {
												Rexec.out.add((String) x2.match);
										} else {
												System.err.println("ERR_RHOST_UNSTRUCT");
										}
								}
								x2.close();
						}
			 */

		}

		private boolean expectOrThrow(Expect x, Pattern p) {
			try {
				x.expectOrThrow(p);
			} catch (Expect.TimeoutException e) {
			} catch (Expect.EOFException e) {
			} catch (IOException e) {
			}
			return x.isSuccess;
		}
	}


	public void waitNumThreadBelowMax() {
		while ( Rexec.threads.size() >= ui.getMaxThreads() ) {
			for ( int i=0; i<Rexec.threads.size(); i++) {
				if ( !Rexec.threads.get(i).isAlive() ) {
					Rexec.threads.remove(Rexec.threads.get(i));
				}
			}
		}
	}

	public void joinThreads() {
		for(int i=0; i<Rexec.threads.size(); i++) {
			try {
				Rexec.threads.get(i).join();
			} catch ( InterruptedException e ) {
				e.printStackTrace();
			}
		}
	}

	public String getOut() {
		String s = new String();
		for ( int i =0; i<Rexec.out.size(); i++ ) {
			s = s + Rexec.out.get(i) + "\n";
		}
		return s;
	}

	public String getOutAsPerlHashStruct() {
		// use this method, if output of remote script execution 
		// - is dump of perl hash struct i.e.
		// { key => value , .. }
		StringBuilder sbStr = new StringBuilder();
		String delim = "," + System.getProperty("line.separator");

		sbStr.append("{" + System.getProperty("line.separator"));
		for ( int i =0; i<Rexec.out.size(); i++ ) {
			if ( i > 0 )
				sbStr.append(delim);
			sbStr.append(Rexec.out.get(i));
		}
		sbStr.append(System.getProperty("line.separator") + "}");
		return sbStr.toString();
	}		
}