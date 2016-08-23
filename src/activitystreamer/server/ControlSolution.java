package activitystreamer.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.KeyFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ControlSolution extends Control {
	private static final Logger log = LogManager.getLogger();

	/*
	 * additional variables as needed
	 */

	JSONParser parser = new JSONParser();
	// information for server itself
	private int localPort;
	private String localHostName;
	private final String authSecret;
	private String secret;
	private String id;
	// info for announce collection
	private ArrayList<Connection> servers = new ArrayList<Connection>();
	private ArrayList<String> hosts = new ArrayList<String>();
	private ArrayList<Integer> ports = new ArrayList<Integer>();
	private ArrayList<String> serverIDs = new ArrayList<String>();
	private ArrayList<String> downServers = new ArrayList<String>();
	private ArrayList<Integer> load = new ArrayList<Integer>();
	// private ArrayList<Integer> loadForServer = new
	// ArrayList<Integer>();
	private ArrayList<String> hostName = new ArrayList<String>();
	private ArrayList<Integer> hostPort = new ArrayList<Integer>();
	// info for authenticated servers and logged users
	private ArrayList<Connection> clients = new ArrayList<Connection>();
	private ArrayList<Boolean> isOld = new ArrayList<Boolean>();
	private ArrayList<String> loggedUser = new ArrayList<String>();
	private ArrayList<String> loggedSecret = new ArrayList<String>();
	// info for register and local storage
	private ArrayList<Connection> register = new ArrayList<Connection>();
	private ArrayList<String> registerUser = new ArrayList<String>();;
	private ArrayList<ArrayList<String>> registerFlag = new ArrayList<ArrayList<String>>();
	private ArrayList<String> usernames = new ArrayList<String>();
	private ArrayList<String> secrets = new ArrayList<String>();


	// *******************************new protocol
	//////////////////////////////////////
	String algorithm = "RSA";
	PrivateKey privKey;
	PublicKey pubKey;
	private ArrayList<PublicKey> Keys = new ArrayList<PublicKey>();
	Cipher cipher;

	String algorithmForC = "AES";
	Cipher cipherForC;
	SecretKey sharedKey;
	///////////////////////////////////////
	private String backupHostO;
	private int backupPortO;
	// back for myself, when outgoing down use it
	private String backupHostM;
	private int backupPortM;

	// since control and its subclasses are singleton, we get the
	/////////////////////////////////////// singleton this
	/////////////////////////////////////// way
	// *******************************new protocol

	public static ControlSolution getInstance() {
		if (control == null) {
			control = new ControlSolution();
		}
		return (ControlSolution) control;
	}

	public ControlSolution() {
		super();
		/*
		 * Do some further initialization here if necessary
		 */
		// initialization for server info
		localPort = Settings.getLocalPort();
		localHostName = Settings.getLocalHostname();
		id = Settings.nextSecret();
		secret = Settings.getSecret();
		if (secret == null) {
			authSecret = Settings.nextSecret();
			System.out.println(
				"The Secret to connect to the server: " + authSecret);
		} else {
			authSecret = secret;
		}
		// *******************************new protocol
		// Generate public/private key pair

		try {
			// pub/priv key
			KeyPairGenerator keyGen = KeyPairGenerator
				.getInstance(algorithm);
			keyGen.initialize(2048);
			KeyPair keyPair = keyGen.genKeyPair();
			this.privKey = keyPair.getPrivate();
			this.pubKey = keyPair.getPublic();
			// System.out.println("line120 pub myself"+this.pubKey);
			this.cipher = Cipher.getInstance(this.algorithm);
			// shared
			KeyGenerator keyGenerator = KeyGenerator
				.getInstance(this.algorithmForC);
			this.sharedKey = keyGenerator.generateKey();
			System.out.println(this.sharedKey);
			this.cipherForC = Cipher.getInstance(this.algorithmForC);
			this.cipherForC.init(Cipher.ENCRYPT_MODE, sharedKey);// server
																	// only
																	// uses
																	// it
																	// to
																	// encrypt

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// check if we should initiate a connection and do so if
		// necessary
		initiateConnection();
		// start the server's activity loop
		// it will call doActivity every few seconds
		start();
	}
	// *******************************new protocol

	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s)
		throws IOException {
		Connection con = super.incomingConnection(s);
		/*
		 * do additional things here
		 */
		// nothing is needed to do here
		return con;
	}

	/*
	 * a new outgoing connection
	 */
	@Override
	public Connection outgoingConnection(Socket s)
		throws IOException {
		Connection con = super.outgoingConnection(s);
		/*
		 * do additional things here
		 */
		// try to authenticate to another server
		JSONObject obj = new JSONObject();
		obj.put("command", "AUTHENTICATE");
		obj.put("secret", this.secret);

		// *******************************new protocol
		// change format
		byte[] bytes = this.pubKey.getEncoded();
		String base64String = Base64.encodeBase64String(bytes);
		obj.put("pubKey", base64String);
		obj.put("hostname", this.localHostName);
		obj.put("port", this.localPort);
		//
		// *******************************new protocol

		con.writeMsg(obj.toString());
		this.servers.add(con);
		this.hosts.add(new String());
		this.ports.add(0);
		this.Keys.add(this.pubKey);
		return con;
	}

	/*
	 * the connection has been closed
	 */

	// *******************************new protocol
	@Override
	public void connectionClosed(Connection con,
		boolean isException) {
		super.connectionClosed(con, isException);
		/*
		 * do additional things here
		 */
		// nothing to do...
		if (servers.indexOf(con) != -1) {
			for (int i = 0; i < serverIDs.size(); i++) {
				if (this.hosts.get(this.servers.indexOf(con)).equals(this.hostName.get(i))
					&& this.ports.get(this.servers.indexOf(con)).equals(this.hostPort.get(i))) {
					// find if the server in local storage
					this.downServers.add(this.serverIDs.get(i));
					System.out.println(
						"Server down:" + this.serverIDs.get(i));
					// delete the data
					this.hostName.remove(i);
					this.hostPort.remove(i);
					this.load.remove(i);
					this.serverIDs.remove(i);
				}
			}
			if (this.hosts.get(this.servers.indexOf(con))
				.equals(this.backupHostO)
				&& this.ports.get(
					this.servers.indexOf(con)) == this.backupPortO) {
				// do something because backup for others is down
				
				this.Keys.remove(this.servers.indexOf(con));
				this.hosts.remove(this.servers.indexOf(con));
				this.ports.remove(this.servers.indexOf(con));
				this.servers.remove(con);
				if (this.servers.size() == 0) {
					// no other severs available
					this.backupHostO = null;
					this.backupPortO = 0;
					this.broadcastBackup(null);
				} else {
					// select the 1st as backup
					this.backupHostO = this.hosts.get(0);
					this.backupPortO = this.ports.get(0);
					this.broadcastBackup(this.servers.get(0));
				}

				// System.out.println("others: " + this.backupHostO +
				// ":"
				// + this.backupPortO);
				// this.broadcastBackup(con);
			} else {
				this.Keys.remove(this.servers.indexOf(con));
				this.hosts.remove(this.servers.indexOf(con));
				this.ports.remove(this.servers.indexOf(con));
				this.servers.remove(con);
			}
			if (this.backupHostM != null) {
				try {
					Socket s = new Socket(this.backupHostM,
						this.backupPortM);
					this.outgoingConnection(s);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		} else {
			if (this.clients.indexOf(con) != -1) {
				this.loggedUser.remove(this.clients.indexOf(con));
				this.loggedSecret.remove(this.clients.indexOf(con));
				this.isOld.remove(this.clients.indexOf(con));
				this.clients.remove(con);
			}
		}
		this.doActivity();
	}
	// *******************************new protocol

	// *******************************new protocol
	private void broadcastBackup(Connection con) {
		JSONObject object = new JSONObject();
		object.put("command", "BACK_UP");
		object.put("hostname", this.backupHostO);
		object.put("port", this.backupPortO);
		try {
			// encryption
			String s = this.encryt(object.toString(), false);
			for (int i = 0; i < this.clients.size(); i++) {
				if (isOld.get(i) == false)
					// only new clients
					clients.get(i).writeMsg(s);
			}
			s = this.encryt(object.toString(), true);
			for (int i = 0; i < this.servers.size(); i++) {
				if (servers.get(i) != con)
					if (Keys.get(i) != this.pubKey)
						// only new servers
						servers.get(i).writeMsg(s);
			}
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}

		if (con != null)
			if (Keys.get(servers.indexOf(con)) != this.pubKey) {
				// new server
				object.replace("hostname", null);
				object.replace("port", 0);
				try {
					// encryption
					String s = this.encryt(object.toString(), true);
					con.writeMsg(s);
				} catch (InvalidKeyException
					| IllegalBlockSizeException
					| BadPaddingException e) {
					e.printStackTrace();
				}
			}
	}
	// *******************************new protocol


	/*
	 * process incoming msg, from connection con return true if the
	 * connection should be closed, false otherwise
	 */
	@Override
	public synchronized boolean process(Connection con, String msg) {
		/*
		 * do additional work here return true/false as appropriate
		 */
		/////////////////////////////
		try {
			msg = this.decrypt(msg, con);
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e1) {
			System.out.println(msg);
		}
		// log.info("Receiving msg: " + line);
		JSONObject obj;
		try {
			obj = (JSONObject) parser.parse(msg);
			Object command = obj.get("command");
			// chect command first
			if (command == null) {
				// missing command
				if (obj.get("ISOLD") == null)
					sendMsg(con, "INVALID_MESSAGE",
						"the received message did not contain a command",
						true, false);
				else
					sendMsg(con, "INVALID_MESSAGE",
						"the received message did not contain a command",
						false, false);
				return true;
			} else {
				// process command
				switch (command.toString()) {
				case "CLOSE CONNECTION":
					if (obj.get("ISOLD") == null)
						sendMsg(con, "CLOSE CONNECTION", "", true,
							false);
					else
						sendMsg(con, "CLOSE CONNECTION", "", false,
							false);
					if (clients.indexOf(con) != -1) {
						this.loggedUser
							.remove(this.clients.indexOf(con));
						this.loggedSecret
							.remove(this.clients.indexOf(con));
						this.isOld.remove(this.clients.indexOf(con));
						this.clients.remove(con);
					}
					return true;
				case "AUTHENTICATE":
					return this.authentication(con, obj);
				case "INVALID_MESSAGE":
					return this.invalidMsg(con, obj);
				case "AUTHENTICATION_FAIL":
					return this.authenticationFail(con, obj);
				case "AUTHENTICATION_SUCCESS":
					return this.authenticationSuccess(con, obj);
				case "BACK_UP":
					return this.setbackup(con, obj);
				case "LOGIN":
					return this.login(con, obj);
				case "LOGOUT":
					return this.logout(con, obj);
				case "ACTIVITY_MESSAGE":
					return this.activityMsg(con, obj);
				case "SERVER_ANNOUNCE":
					return this.serverAnnounce(con, obj);
				case "ACTIVITY_BROADCAST":
					return this.activityBroadcast(con, obj);
				case "REGISTER":
					return this.register(con, obj);
				case "LOCK_REQUEST":
					return this.lockRequest(con, obj);
				case "LOCK_DENIED":
					return this.lockDenied(con, obj);
				case "LOCK_ALLOWED":
					return this.lockAllowed(con, obj);
				default:
					// invalid command received
					if (obj.get("ISOLD") == null)
						sendMsg(con, "INVALID_MESSAGE",
							"invalid command", true, false);
					else
						sendMsg(con, "INVALID_MESSAGE",
							"invalid command", false, false);
					int key = clients.indexOf(con);
					if (key != -1) {
						this.loggedUser.remove(key);
						this.loggedSecret.remove(key);
						this.isOld.remove(key);
						clients.remove(con);
					} else {
						this.Keys.remove(this.servers.indexOf(con));
						this.hosts.remove(this.servers.indexOf(con));
						this.ports.remove(this.servers.indexOf(con));
						servers.remove(con);
					}
					return true;
				}
			}
		} catch (ParseException e) {
			e.printStackTrace();

			// *******************************new protocol
			int key = clients.indexOf(con);
			if (key != -1) {
				this.loggedUser.remove(key);
				this.loggedSecret.remove(key);
				this.isOld.remove(key);
				clients.remove(con);
			// *******************************new protocol
				sendMsg(con, "INVALID_MESSAGE",
					"JSON parse error while parsing message", true,
					false);
			} else {
			// *******************************new protocol
				this.Keys.remove(this.servers.indexOf(con));
				this.hosts.remove(this.servers.indexOf(con));
				this.ports.remove(this.servers.indexOf(con));
				servers.remove(con);
			// *******************************new protocol
				sendMsg(con, "INVALID_MESSAGE",
					"JSON parse error while parsing message", true,
					true);
			}
			return true;
		}
		///////////////////////////////
	}


	// *******************************new protocol
	private boolean setbackup(Connection con, JSONObject obj) {
		if (obj.get("hostname") != null
			&& (this.localHostName != obj.get("hostname").toString()
				|| this.localPort != Integer
					.parseInt(obj.get("port").toString()))) {
			this.backupHostM = obj.get("hostname").toString();
			this.backupPortM = Integer
				.parseInt(obj.get("port").toString());
		} else {
			this.backupHostM = null;
			this.backupPortM = 0;
		}
//		System.out.println(
//			"BFM: " + this.backupHostM + ":" + this.backupPortM);
		return false;
	}
	// *******************************new protocol

	private boolean authenticationSuccess(Connection con,
		JSONObject obj) {
		// new servers new protocol
		this.usernames = (ArrayList<String>) obj.get("users");
		this.secrets = (ArrayList<String>) obj.get("secrets");

		// *******************************new protocol
		String base64String = obj.get("pubKey").toString();
		byte[] backToBytes = Base64.decodeBase64(base64String);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			backToBytes);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKeyForCon = keyFactory
				.generatePublic(publicKeySpec);
			// System.out.println("373 key gotten for com: "+
			// publicKeyForCon);
			this.Keys.set(this.servers.indexOf(con), publicKeyForCon);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		if (obj.get("backhost") != null) {
			this.backupHostM = obj.get("backhost").toString();
			this.backupPortM = Integer
				.parseInt(obj.get("backport").toString());
		}
//		System.out.println(
//			"BFM: " + this.backupHostM + ":" + this.backupPortM);
		this.backupHostO = obj.get("hostname").toString();
		this.backupPortO = Integer
			.parseInt(obj.get("port").toString());
		this.hosts.set(servers.indexOf(con), this.backupHostO);
		this.ports.set(servers.indexOf(con), this.backupPortO);
		this.broadcastBackup(con);
//		System.out.println(
//			"BFO:" + this.backupHostO + ":" + this.backupPortO);
		return false;
	}
	// *******************************new protocol


	/*
	 * Called once every few seconds Return true if server should shut
	 * down, false otherwise
	 */
	@Override
	public boolean doActivity() {
		/*
		 * do additional work here return true/false as appropriate
		 */
		// broadcast the server announce regularly
		JSONObject obj = new JSONObject();
		obj.put("command", "SERVER_ANNOUNCE");
		obj.put("id", this.id);
		obj.put("load", this.clients.size());
		obj.put("loadForServer", this.servers.size());
		obj.put("hostname", this.localHostName);
		obj.put("port", this.localPort);
		obj.put("down", this.downServers);

		// *******************************new protocol
		try {
			String s = this.encryt(obj.toString(), true);
			for (int i = 0; i < servers.size(); i++) {
				if (Keys.get(i) != this.pubKey)
					servers.get(i).writeMsg(s);
				else
					servers.get(i).writeMsg(obj.toString());
			}
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}
		// *******************************new protocol

		System.out.println("Connected servers: " + this.servers.size()
			+ ";Connected clients: " + this.clients.size());
		this.downServers = new ArrayList<String>();
		return false;
	}

	/*
	 * Other methods as needed
	 */

	/*
	 * Called when a authentication message arrive
	 */
	@SuppressWarnings("unchecked")
	private boolean authentication(Connection con, JSONObject obj) {
		Object o = obj.get("secret");
		// check secret first
		if (o == null) {
			sendMsg(con, "INVALID_MESSAGE", "Missing secret", true,
				true);
			return true;
		}
		String secret = o.toString();
		if (authSecret.equals(secret)) {
			// secret matches
			if (servers.indexOf(con) == -1) {
				// not authenticated yet
				servers.add(con);

				// *******************************new protocol
				// get pubKey
				if (obj.get("pubKey") != null) {
					// new servers
					this.hosts.add(obj.get("hostname").toString());
					this.ports.add(
						Integer.parseInt(obj.get("port").toString()));
					// server with new proto
					String base64String = obj.get("pubKey")
						.toString();
					byte[] backToBytes = Base64
						.decodeBase64(base64String);

					EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
						backToBytes);
					KeyFactory keyFactory;
					try {
						keyFactory = KeyFactory.getInstance("RSA");
						PublicKey publicKeyForCon = keyFactory
							.generatePublic(publicKeySpec);
						// System.out.println("460 get
						// key"+publicKeyForCon);
						this.Keys.add(publicKeyForCon);
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
					} catch (InvalidKeySpecException e) {
						e.printStackTrace();
					}
					JSONObject object = new JSONObject();
					object.put("command", "AUTHENTICATION_SUCCESS");
					object.put("users", this.usernames);
					object.put("secrets", this.secrets);
					object.put("hostname", this.localHostName);
					object.put("port", this.localPort);
					if (this.backupHostO == null) {
						object.put("backhost", null);
						object.put("backport", 0);
					} else {
						object.put("backhost", this.backupHostO);
						object.put("backport", this.backupPortO);
					}
					// format changes
					byte[] privateKeyBytes = this.pubKey.getEncoded();
					base64String = Base64
						.encodeBase64String(privateKeyBytes);
					object.put("pubKey", base64String);
					con.writeMsg(object.toString());
					// System.out.println("aut:others: "+
					// this.backupHostO + ":" + this.backupPortO);
					if (this.backupHostO == null) {
						this.backupHostO = obj.get("hostname")
							.toString();
						this.backupPortO = Integer
							.parseInt(obj.get("port").toString());
						this.broadcastBackup(con);
					}
//					System.out.println("BFO: " + this.backupHostO
//						+ ":" + this.backupPortO);
				} else {
					// old
					this.hosts.add(new String());
					this.ports.add(0);
					this.Keys.add(this.pubKey);
				}
				return false;
				// *******************************new protocol

			} else {
				// already be authencated
				this.Keys.remove(this.servers.indexOf(con));
				this.hosts.remove(this.servers.indexOf(con));
				this.ports.remove(this.servers.indexOf(con));
				servers.remove(con);
				sendMsg(con, "AUTHENTICATION_FAIL",
					"server has already been authenticated", true,
					true);
				return true;
			}
		} else

		{
			// secret mismatched
			sendMsg(con, "AUTHENTICATION_FAIL",
				"the supplied secret is incorrect: " + secret, true,
				true);
			return true;
		}

	}

	/*
	 * Called when a command indicating invalid message arrive
	 */
	private boolean invalidMsg(Connection con, JSONObject obj) {
		// receive command indicating invalid msg
		String info = obj.get("info").toString();
		if (info != null)
			log.info(info);

		// *******************************new protocol
		int key = clients.indexOf(con);
		if (key != -1) {
			this.loggedUser.remove(key);
			this.loggedSecret.remove(key);
			this.isOld.remove(key);
			clients.remove(con);
		} else {
			this.Keys.remove(this.servers.indexOf(con));
			this.hosts.remove(this.servers.indexOf(con));
			this.ports.remove(this.servers.indexOf(con));
			servers.remove(con);
		}
		// *******************************new protocol

		return true;
	}

	/*
	 * Called when a authentication fail message arrive
	 */
	private boolean authenticationFail(Connection con,
		JSONObject obj) {
		// authentication fails
		this.Keys.remove(this.servers.indexOf(con));
		servers.remove(con);
		String info = obj.get("info").toString();
		if (info != null)
			log.info(info);
		return true;
	}

	/*
	 * Called when a login message arrive
	 */
	@SuppressWarnings("unchecked")
	private boolean login(Connection con, JSONObject obj) {
		// check username first
		Object user = obj.get("username").toString();
		if (user == null) {
			// miss username
			sendMsg(con, "INVALID_MESSAGE", "Missing username", true,
				false);
			return true;
		}
		if (user.equals("anonymous")) {
			// anonymous user
			// sendMsg(con, "LOGIN_SUCCESS",
			// "logged in as user " + user);

			// *******************************new protocol
			JSONObject o = new JSONObject();
			o.put("command", "LOGIN_SUCCESS");
			o.put("info", "logged in as user " + user);
			o.put("hostname", this.backupHostO == null ? null
				: this.backupHostO.toString());
			o.put("port", this.backupPortO);
			// System.out.println(this.sharedKey.toString());
			byte[] sharedkey = this.sharedKey.getEncoded();
			String base64String = Base64
				.encodeBase64String(sharedkey);
			o.put("SharedKey", base64String);
			System.out.println(o.toString());
			con.writeMsg(o.toString());
			if (serverIDs.size() == 0) {
				// if no other servers in the network, no need for
				// redirection
				this.clients.add(con);
				this.loggedUser.add(user.toString());
				this.loggedSecret.add("");
				if (obj.get("ISOLD") == null)
					this.isOld.add(true);
				else
					this.isOld.add(false);
				return false;
			} else
				// redirect the user if necessary
				if (obj.get("ISOLD") == null)
				return redirect(con, user, secret, true);
			else
				return redirect(con, user, secret, false);
		}
		// *******************************new protocol

		Object secret = obj.get("secret").toString();
		if (secret == null) {
			// check secret
			sendMsg(con, "INVALID_MESSAGE", "Missing secret", true,
				false);
			return true;
		}
		if (this.loggedUser.indexOf(user.toString()) != -1) {
			// user has already logged in
			sendMsg(con, "LOGIN_FAILED",
				"username has already been logged", true, false);
			return true;
		}
		if (usernames.indexOf(user.toString()) == -1) {
			// username cannot be found in local storage
			sendMsg(con, "LOGIN_FAILED", "username not found", true,
				false);
			return true;
		} else {
			if (secrets.get(usernames.indexOf(user.toString()))
				.equals(secret.toString())) {
				// username and secret match
				// sendMsg(con, "LOGIN_SUCCESS",
				// "logged in as user " + user);

				// *******************************new protocol
				JSONObject o = new JSONObject();
				o.put("command", "LOGIN_SUCCESS");
				o.put("info", "logged in as user " + user);
				o.put("hostname", this.backupHostO == null ? null
					: this.backupHostO.toString());
				o.put("port", this.backupPortO);
				// System.out.println(this.sharedKey.toString());
				byte[] sharedkey = this.sharedKey.getEncoded();
				String base64String = Base64
					.encodeBase64String(sharedkey);
				o.put("SharedKey", base64String);
				// old and new the same
				con.writeMsg(o.toString());
				// *******************************new protocol

				if (serverIDs.size() == 0) {
					// no other servers in the network
					this.clients.add(con);
					this.loggedUser.add(user.toString());
					this.loggedSecret.add(secret.toString());
					if (obj.get("ISOLD") == null)
						this.isOld.add(true);
					else
						this.isOld.add(false);
					return false;
				} else
					// redirect if necessary
					if (obj.get("ISOLD") == null)
					return redirect(con, user, secret, true);
				else
					return redirect(con, user, secret, false);
			} else {
				// mismatch
				sendMsg(con, "LOGIN_FAILED",
					"attempt to login with wrong secret", true,
					false);
				return true;
			}
		}
	}

	/*
	 * Called when an activity message arrive
	 */
	private boolean activityMsg(Connection con, JSONObject obj)
		throws ParseException {
		if (clients.indexOf(con) == -1) {
			// client has not logged in yet
			sendMsg(con, "AUTHENTICATION_FAIL",
				"not logged in client", true, false);
			return true;
		}
		Object user = obj.get("username");
		Object secret = obj.get("secret");
		Object activity = obj.get("activity");

		if (user == null) {
			// missing username
			if (this.isOld.get(this.clients.indexOf(con)) == true)
				sendMsg(con, "INVALID_MESSAGE", "Missing username",
					true, false);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing username",
					false, false);
			this.loggedUser.remove(this.clients.indexOf(con));
			this.loggedSecret.remove(this.clients.indexOf(con));
			this.isOld.remove(this.clients.indexOf(con));
			clients.remove(con);
			return true;
		}

		if (!user.toString().equals("anonymous")) {
			// not anonymous
			if (secret == null) {
				// missing secret
				if (this.isOld.get(this.clients.indexOf(con)) == true)
					sendMsg(con, "INVALID_MESSAGE", "Missing secret",
						true, false);
				else
					sendMsg(con, "INVALID_MESSAGE", "Missing secret",
						false, false);
				this.loggedUser.remove(this.clients.indexOf(con));
				this.loggedSecret.remove(this.clients.indexOf(con));
				this.isOld.remove(this.clients.indexOf(con));
				clients.remove(con);
				return true;
			}
			if (this.loggedUser.isEmpty()
				|| (this.loggedUser.indexOf(user.toString()) == -1)) {
				// user has not logged in yet
				sendMsg(con, "AUTHENTICATION_FAIL",
					user.toString() + " has not logged in yet", true,
					false);
				this.loggedUser.remove(this.clients.indexOf(con));
				this.loggedSecret.remove(this.clients.indexOf(con));
				this.isOld.remove(this.clients.indexOf(con));
				clients.remove(con);
				return true;

			} else if (!this.loggedSecret
				.get(loggedUser.indexOf(user.toString()))
				.equals(secret.toString())) {
				// mismatch
				sendMsg(con, "AUTHENTICATION_FAIL",
					"do not match the logged in the user", true,
					false);
				this.loggedUser.remove(this.clients.indexOf(con));
				this.loggedSecret.remove(this.clients.indexOf(con));
				this.isOld.remove(this.clients.indexOf(con));
				clients.remove(con);
				return true;
			}
		}

		if (activity == null) {
			// missing activity
			if (this.isOld.get(this.clients.indexOf(con)) == true)
				sendMsg(con, "INVALID_MESSAGE", "Missing activity",
					true, false);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing activity",
					false, false);
			this.loggedUser.remove(this.clients.indexOf(con));
			this.loggedSecret.remove(this.clients.indexOf(con));
			this.isOld.remove(this.clients.indexOf(con));
			clients.remove(con);
			return true;
		}

		// verify successfully
		JSONObject o = (JSONObject) parser.parse(activity.toString());
		// add authenticated_user to activity object
		o.put("authenticated_user", user.toString());
		// broadcast the activity
		JSONObject j = new JSONObject();
		j.put("command", "ACTIVITY_BROADCAST");
		j.put("activity", o);
		try {
			String s = this.encryt(j.toString(), true);
			for (int i = 0; i < servers.size(); i++)
				if (this.Keys.get(i) == this.pubKey) {
					System.out.println(
						"msg broad to old.................:");
					servers.get(i).writeMsg(j.toString());
				} else {
					System.out.println(
						"msg broad to new...................:");
					servers.get(i).writeMsg(s);
				}
			s = this.encryt(j.toString(), false);
			for (int i = 0; i < clients.size(); i++)
				if (clients.get(i) != con)
					if (this.isOld.get(i) == true)
						clients.get(i).writeMsg(j.toString());
					else
						clients.get(i).writeMsg(s);
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Called when a logout message arrive
	 */
	private boolean logout(Connection con, JSONObject obj) {
		if (this.isOld.get(this.clients.indexOf(con)) == true)
			sendMsg(con, "CLOSE CONNECTION", "", true, false);
		else
			sendMsg(con, "CLOSE CONNECTION", "", false, false);

		this.loggedUser.remove(this.clients.indexOf(con));
		this.loggedSecret.remove(this.clients.indexOf(con));
		this.isOld.remove(this.clients.indexOf(con));
		this.clients.remove(con);
		return true;
	}

	/*
	 * Called when a server announce arrive
	 */
	private boolean serverAnnounce(Connection con, JSONObject obj) {
		// System.out.println(obj.toString());
		if (servers.indexOf(con) == -1) {
			// unauthenticated server
			sendMsg(con, "INVALID_MESSAGE", "unauthenticated server",
				true, true);
			return true;
		}
		// check id first
		Object o = obj.get("id");
		if (o == null) {
			// missing id
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing id", true,
					true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing id", false,
					true);
			return true;
		}
		// check the load
		o = obj.get("load");
		if (o == null) {
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing load", true,
					true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing load", false,
					true);
			return true;
		}
		// check hostname
		o = obj.get("hostname");
		if (o == null) {
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing hostname",
					true, true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing hostname",
					false, true);
			return true;
		}
		// check port number
		o = obj.get("port");
		if (o == null) {
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing port", true,
					true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing port", false,
					true);
			return true;
		}

		if (serverIDs.indexOf(obj.get("id").toString()) == -1) {
			// receive new server id, add info to local storage
			serverIDs.add(obj.get("id").toString());
			load.add(Integer.parseInt(obj.get("load").toString()));
			// loadForServer.add(Integer
			// .parseInt(obj.get("loadForServer").toString()));
			hostName.add(obj.get("hostname").toString());
			hostPort
				.add(Integer.parseInt(obj.get("port").toString()));
		} else {
			// known server id, update info to the local storage
			load.set(serverIDs.indexOf(obj.get("id").toString()),
				Integer.parseInt(obj.get("load").toString()));
			// loadForServer.set(
			// serverIDs.indexOf(obj.get("id").toString()), Integer
			// .parseInt(obj.get("loadForServer").toString()));
			hostName.set(serverIDs.indexOf(obj.get("id").toString()),
				obj.get("hostname").toString());
			hostPort.set(serverIDs.indexOf(obj.get("id").toString()),
				Integer.parseInt(obj.get("port").toString()));
		}

		// *******************************new protocol
		ArrayList<String> down = (ArrayList<String>) obj.get("down");
		for (int i = 0; i < down.size(); i++)
			if(this.serverIDs.indexOf(down.get(i)) != -1){
				//find down server in the list
				//delete it
				this.hostName.remove(this.serverIDs.indexOf(down.get(i)));
				this.hostPort.remove(this.serverIDs.indexOf(down.get(i)));
				this.load.remove(this.serverIDs.indexOf(down.get(i)));
				this.serverIDs.remove(this.serverIDs.indexOf(down.get(i)));
				System.out.println("Remove: "+ down.get(i));
			}
		// broadcast the receiving server announce
		try {
			String s = this.encryt(obj.toString(), true);
			for (int i = 0; i < servers.size(); i++)
				if (servers.get(i) != con) {
					if (Keys.get(i) != this.pubKey)
						servers.get(i).writeMsg(s);
					else
						servers.get(i).writeMsg(obj.toString());
				}
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}
		// System.out.println(this.serverIDs);
		return false;
	}
	// *******************************new protocol

	/*
	 * Called when a activity broadcast arrive
	 */
	private boolean activityBroadcast(Connection con,
		JSONObject obj) {
		if (servers.indexOf(con) == -1) {
			// unauthenticated server
			sendMsg(con, "INVALID_MESSAGE", "unauthenticated server",
				true, true);
			return true;
		}
		// check activity
		Object o = obj.get("activity");
		if (o == null) {
			// missing activity
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing activity",
					true, true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing activity",
					false, true);
			return true;
		}

		// *******************************new protocol
		// broadcast the activity
		try {
			String s = this.encryt(obj.toString(), true);
			for (int i = 0; i < this.servers.size(); i++)
				if (this.servers.get(i) != con)
					if (this.Keys.get(i) == this.pubKey)
						servers.get(i).writeMsg(obj.toString());
					else
						servers.get(i).writeMsg(s);
			s = this.encryt(obj.toString(), false);
			for (int i = 0; i < this.clients.size(); i++)
				if (this.isOld.get(i) == true)
					clients.get(i).writeMsg(obj.toString());
				else
					clients.get(i).writeMsg(s);
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}
		return false;
		// *******************************new protocol
	}

	/*
	 * Called when a register message arrive
	 */
	private boolean register(Connection con, JSONObject obj) {
		if (this.clients.indexOf(con) != -1) {
			// user has already logged
			if (this.isOld.get(clients.indexOf(con)) == true)
				sendMsg(con, "INVALID_MESSAGE",
					"user has already logged", true, false);
			else
				sendMsg(con, "INVALID_MESSAGE",
					"user has already logged", false, false);
			return true;
		}
		// check username and secret
		Object user = obj.get("username");
		Object secret = obj.get("secret");
		if (user == null || secret == null) {
			// missing username or secret
			sendMsg(con, "INVALID_MESSAGE",
				"Missing username or secret", true, false);
			return true;
		}

		if (usernames.indexOf(user.toString()) != -1) {
			// usernames has already been known by the server
			sendMsg(con, "REGISTER_FAILED",
				user.toString()
					+ " is already registered with the system",
				true, false);
			return true;
		}

		if (serverIDs.size() == 0) {
			// no other servers in the network, register success, add
			// info to
			// local storage
			usernames.add(user.toString());
			secrets.add(secret.toString());
			this.sendMsg(con, "REGISTER_SUCCESS",
				"register success for " + user.toString(), true,
				false);
		}

		// add to register list
		this.registerUser.add(user.toString());
		this.register.add(con);
		ArrayList<String> flag = new ArrayList<String>();
		for (int i = 0; i < serverIDs.size(); i++)
			flag.add(serverIDs.get(i));
		this.registerFlag.add(flag);
		// broadcast the lock request.
		JSONObject o = new JSONObject();
		o.put("command", "LOCK_REQUEST");
		o.put("username", obj.get("username"));
		o.put("secret", obj.get("secret"));
		String s;
		try {
			s = this.encryt(o.toString(), true);
			for (int i = 0; i < this.servers.size(); i++) {
				if (this.Keys.get(i) == this.pubKey)
					this.servers.get(i).writeMsg(o.toString());
				else
					this.servers.get(i).writeMsg(s);
			}
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}
		return false;
	}

	/*
	 * Called when a lock request arrive
	 */
	private boolean lockRequest(Connection con, JSONObject obj) {
		if (this.servers.indexOf(con) == -1) {
			// unauthenticated server
			sendMsg(con, "INVALID_MESSAGE", "unauthenticated server",
				true, true);
			return true;
		}
		// check username and secret
		Object user = obj.get("username");
		Object secret = obj.get("secret");
		if (user == null || secret == null) {
			// mising username or secret
			if (this.Keys
				.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE",
					"Missing username or secret", true, true);
			else
				sendMsg(con, "INVALID_MESSAGE",
					"Missing username or secret", false, true);
			return true;
		}
		JSONObject o = new JSONObject();
		if (usernames.indexOf(user.toString()) != -1) {
			// username has been already known
			o.put("command", "LOCK_DENIED");
			o.put("username", obj.get("username"));
			o.put("secret", obj.get("secret"));
		} else {
			// new username
			o.put("command", "LOCK_ALLOWED");
			o.put("username", obj.get("username"));
			o.put("secret", obj.get("secret"));
			o.put("server", this.id);
			// add new info to local storage
			usernames.add(user.toString());
			secrets.add(secret.toString());
		}
		// broadcast the lock request
		try {
			String s = this.encryt(obj.toString(), true);
			for (int i = 0; i < this.servers.size(); i++)
				if (this.servers.get(i) != con)
					if (Keys.get(i) == this.pubKey)
						servers.get(i).writeMsg(obj.toString());
					else
						servers.get(i).writeMsg(s);
			// broadcast the lock allowed or denied
			s = this.encryt(o.toString(), true);
			for (int i = 0; i < this.servers.size(); i++) {
				if (Keys.get(i) == this.pubKey)
					servers.get(i).writeMsg(o.toString());
				else
					servers.get(i).writeMsg(s);
			}
		} catch (InvalidKeyException | IllegalBlockSizeException
			| BadPaddingException e) {
			e.printStackTrace();
		}

		return false;
	}

	/*
	 * Called when a lock allowed message arrive
	 */
	private boolean lockAllowed(Connection con, JSONObject obj) {
		if (this.servers.indexOf(con) == -1) {
			// unauthenticated server
			sendMsg(con, "INVALID_MESSAGE", "unauthenticated server",
				true, true);
			return true;
		}
		// check info
		Object user = obj.get("username");
		Object secret = obj.get("secret");
		Object server = obj.get("server");
		if (user == null || secret == null || server == null) {
			// missing some of the info
			if (this.Keys.get(servers.indexOf(con)) == this.pubKey)
				sendMsg(con, "INVALID_MESSAGE", "Missing information",
					true, true);
			else
				sendMsg(con, "INVALID_MESSAGE", "Missing information",
					false, true);
			return true;
		}
		// check in register list
		if (this.registerUser.indexOf(user.toString()) != -1) {
			// the username is saved in the register list, modify the
			// flag
			this.registerFlag
				.get(this.registerUser.indexOf(user.toString()))
				.remove(server.toString());
			if (this.registerFlag
				.get(this.registerUser.indexOf(user.toString()))
				.isEmpty()) {
				// all servers reply lock allowed, register success,
				// add info to
				// local storage
				usernames.add(user.toString());
				secrets.add(secret.toString());
				// if (this.Keys
				// .get(servers.indexOf(con)) == this.pubKey)
				// sendMsg(
				// this.register.get(this.registerUser
				// .indexOf(user.toString())),
				// "REGISTER_SUCCESS",
				// "register success for " + user.toString(),
				// true);
				// else
				sendMsg(
					this.register.get(
						this.registerUser.indexOf(user.toString())),
					"REGISTER_SUCCESS",
					"register success for " + user.toString(), true,
					false);
				// delete user from register list
				this.register.remove(
					this.registerUser.indexOf(user.toString()));
				this.registerFlag.remove(
					this.registerUser.indexOf(user.toString()));
				this.registerUser.remove(
					this.registerUser.indexOf(user.toString()));
			}
		} else {
			// if not in the register list, broadcast the lock allowed
			try {
				String s = this.encryt(obj.toString(), true);
				for (int i = 0; i < this.servers.size(); i++)
					if (this.servers.get(i) != con)
						if (Keys.get(i) == this.pubKey)
							servers.get(i).writeMsg(obj.toString());
						else
							servers.get(i).writeMsg(s);
			} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	/*
	 * Called when a lock denied message arrive
	 */
	private boolean lockDenied(Connection con, JSONObject obj) {
		if (this.servers.indexOf(con) == -1) {
			// unauthenticated server
			sendMsg(con, "INVALID_MESSAGE", "unauthenticated server",
				true, true);
			return true;
		}
		// check username and secret
		Object user = obj.get("username");
		Object secret = obj.get("secret");
		if (user == null || secret == null) {
			// missing username or secret
			if (Keys.get(this.servers.indexOf(con)) == this.pubKey)
				// old
				sendMsg(con, "INVALID_MESSAGE",
					"Missing username or secret", true, true);
			else
				sendMsg(con, "INVALID_MESSAGE",
					"Missing username or secret", false, true);
			return true;
		}

		/// check the register list
		if (this.registerUser.indexOf(user.toString()) != -1) {
			// username in the register list
			if (Keys.get(this.servers.indexOf(con)) == this.pubKey)
				sendMsg(
					this.register.get(
						this.registerUser.indexOf(user.toString())),
					"REGISTER_FAILED",
					user.toString()
						+ " is already registered with the system",
					true, false);
			else
				sendMsg(
					this.register.get(
						this.registerUser.indexOf(user.toString())),
					"REGISTER_FAILED",
					user.toString()
						+ " is already registered with the system",
					false, false);
			// close the connection for register fail
			this.register
				.get(this.registerUser.indexOf(user.toString()))
				.closeCon();
			// delete user from register list
			this.register
				.remove(this.registerUser.indexOf(user.toString()));
			this.registerFlag
				.remove(this.registerUser.indexOf(user.toString()));
			this.registerUser
				.remove(this.registerUser.indexOf(user.toString()));
		}
		/// if not in the register list
		else {
			/// check local storage, delete the same data
			int key = usernames.indexOf(user.toString());
			if (key != -1)
				if (secrets.get(key).equals(secret.toString())) {
					secrets.remove(key);
					usernames.remove(key);
				}
			// broadcast lock denied
			try {
				String s = this.encryt(obj.toString(), true);
				for (int i = 0; i < this.servers.size(); i++)
					if (this.servers.get(i) != con)
						if (this.Keys.get(i) == this.pubKey)
							servers.get(i).writeMsg(obj.toString());
						else
							servers.get(i).writeMsg(s);
			} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	/*
	 * Called when a redirection may need to be done
	 */
	private boolean redirect(Connection con, Object user,
		Object secret, boolean isOld) {
		int target = this.clients.size();
		// search the server with minimum load
		int minIndex = load.indexOf(Collections.min(load));
		// check if the minimum load is at least 2 less than the
		// current server
		if (load.get(minIndex) <= target - 2) {
			// if so, send redirect message
			JSONObject obj = new JSONObject();
			obj.put("command", "REDIRECT");
			obj.put("hostname", hostName.get(minIndex));
			obj.put("port", hostPort.get(minIndex));
			try {
				String s = this.encryt(obj.toString(), false);
				if (isOld)
					con.writeMsg(obj.toString());
				else
					con.writeMsg(s);
			} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			;
			return true;
		} else {
			// if not, the user log in the current server
			clients.add(con);
			loggedUser.add(user.toString());
			if (user.toString().equals("anonymous"))
				loggedSecret.add(new String());
			else
				loggedSecret.add(secret.toString());
			this.isOld.add(isOld);
			return false;
		}
	}

	/*
	 * Called when a message is needed to be sent
	 */
	private void sendMsg(Connection con, String command, String info,
		boolean isOld, boolean isServer) {
		JSONObject obj = new JSONObject();
		obj.put("command", command);
		obj.put("info", info);
		if (isOld)
			con.writeMsg(obj.toString());
		else {
			try {
				String s = this.encryt(obj.toString(), isServer);
				con.writeMsg(s);
			} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
				e.printStackTrace();
			}
		}
	}

	// *******************************new protocol
	private String encryt(String s, boolean isServer)
		throws InvalidKeyException, IllegalBlockSizeException,
		BadPaddingException {
		if (isServer) {
			this.cipher.init(Cipher.ENCRYPT_MODE, this.privKey);
			byte[] text = s.getBytes();
			text = this.cipher.doFinal(text);
			s = Base64.encodeBase64String(text);//////
		} else {
			// clients
			this.cipherForC.init(Cipher.ENCRYPT_MODE, this.sharedKey);
			byte[] text = s.getBytes();
			text = this.cipherForC.doFinal(text);
			s = Base64.encodeBase64String(text);//////
		}
		return s;
	}

	private String decrypt(String s, Connection con)
		throws InvalidKeyException, IllegalBlockSizeException,
		BadPaddingException {
		if (servers.indexOf(con) != -1
			&& this.Keys.get(servers.indexOf(con)) != this.pubKey) {
			// System.out.println("decrypt:
			// "+this.Keys.get(servers.indexOf(con)));
			cipher.init(Cipher.DECRYPT_MODE,
				this.Keys.get(servers.indexOf(con)));
			byte[] text = Base64.decodeBase64(s);
			text = cipher.doFinal(text);
			// System.out.println("msg received" + new String(text));
			return new String(text);
		}
		if (clients.indexOf(con) != -1
			&& this.isOld.get(clients.indexOf(con)) == false) {
			cipherForC.init(Cipher.DECRYPT_MODE, this.sharedKey);
			byte[] text = Base64.decodeBase64(s);
			text = this.cipherForC.doFinal(text);
			return new String(text);
		}
		return s;
	}
	// *******************************new protocol

}
