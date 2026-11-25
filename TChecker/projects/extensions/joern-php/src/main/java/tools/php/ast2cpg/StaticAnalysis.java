package tools.php.ast2cpg;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;

import ast.ASTNode;
import ast.expressions.ArgumentList;
import ast.expressions.ArrayIndexing;
import ast.expressions.AssignmentExpression;
import ast.expressions.CallExpressionBase;
import ast.expressions.Expression;
import ast.expressions.NewExpression;
import ast.expressions.PropertyExpression;
import ast.expressions.Variable;
import ast.functionDef.ParameterBase;
import ast.functionDef.ParameterList;
import ast.php.expressions.CoalesceExpression;
import ast.php.expressions.EncapsListExpression;
import ast.php.expressions.ExitExpression;
import ast.php.expressions.IncludeOrEvalExpression;
import ast.php.expressions.MethodCallExpression;
import ast.php.expressions.PrintExpression;
import ast.php.expressions.StaticCallExpression;
import ast.php.functionDef.FunctionDef;
import ast.php.functionDef.Method;
import ast.php.functionDef.Parameter;
import ast.php.functionDef.TopLevelFunctionDef;
import ast.php.statements.EchoStatement;
import ast.statements.jump.ReturnStatement;
import cg.PHPCGFactory;
import cg.ParseVar;
import cg.toTopLevelFile;
import ddg.DataDependenceGraph.DDG;
import inputModules.csv.PHPCSVNodeTypes;
import inputModules.csv.csv2ast.ASTUnderConstruction;
import misc.MultiHashMap;
import misc.Pair;
import outputModules.csv.exporters.CSVCFGExporter;

public class StaticAnalysis  {
	public static Set<Long> sources = PHPCSVEdgeInterpreter.sources;
	public static Set<Long> sinks = new HashSet<Long>();
	public static Set<Long> sqlSanitizers = new HashSet<Long>();
	public static Set<Long> cfgNode = new HashSet<Long>();
	public static MultiHashMap<Long, Long> srcDim = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> srcProp = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> srcGlobal = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> dstGlobal = new MultiHashMap<Long, Long>();
	public static HashMap<Long, Node> ID2Node = new HashMap<Long, Node>();
	public static MultiHashMap<Long, Long> dstProp = new MultiHashMap<Long, Long>();
	public static Node root = new Node((long) 0, new HashMap<String, Long>(), new HashSet<Long>(), new Stack<Long>());
	public static MultiHashMap<Long, Stack<Long>> vulStmts = new MultiHashMap<Long, Stack<Long>>();
	public static Set<Stack<Long>> vulPaths = new HashSet<Stack<Long>>();
	public static Long ID = null;
	public static MultiHashMap<String, Long> name2Stmt = new MultiHashMap<String, Long>();
	private final HashMap<Long, Set<String>> propertiesByFunction = new HashMap<>();
	public static MultiHashMap<Long, Long> caller2callee = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> callee2caller = new MultiHashMap<Long, Long>();
	public static HashSet<Long> validFunc = new HashSet<Long>();
	public static HashSet<Long> unused = new HashSet<Long>();
	public static HashMap<Long, Integer> Edgetimes = new HashMap<Long, Integer>();
	public static HashMap<Long, Integer> Edgesize = new HashMap<Long, Integer>();
	public static HashMap<Long, Integer> savesize = new HashMap<Long, Integer>();
	public static HashMap<Long, Boolean> active = new HashMap<Long, Boolean>();
	public static MultiHashMap<Long, Long> sourceFunc = new MultiHashMap<Long, Long>(); 
	public static MultiHashMap<Long, Long> clean = new MultiHashMap<Long, Long>();
	public static HashSet<Long> loop = new HashSet<Long>();
	public static HashSet<Long> forloop = new HashSet<Long>();
	public static MultiHashMap<Long, Long> srcStmt = new MultiHashMap<Long, Long>();
	private final Set<Long> directOutputStatements = new HashSet<>();
	public static HashMap<Long, Integer> loopsize = new HashMap<Long, Integer>(); 
	public static HashSet<Long> allTargets = new HashSet<Long>();
	public static HashMap<Long, HashMap<String, Long>> addInter = new HashMap<Long, HashMap<String, Long>>(); 
	public static HashMap<Long, HashMap<String, Long>> removeInter = new HashMap<Long, HashMap<String, Long>>();
	public static HashMap<Long, Boolean> addIntro = new HashMap<Long, Boolean>();
	public static HashMap<Long, Stack<Long>> sum = new HashMap<Long, Stack<Long>>();
	public static HashSet<Long> expList = new HashSet<Long>();
	public static HashMap<Long, Long> cfgPredecessor = new HashMap<Long, Long>();  // 璁板綍CFG鍓嶉┍鍏崇郴
	public static HashMap<Long, String> dstDim = new HashMap<Long, String>();
	
	// 娣诲姞璋冪敤鏍堣拷韪拰閫掑綊娣卞害闄愬埗锛岄槻姝㈡棤闄愰€掑綊
	private static ThreadLocal<Set<Long>> traverseCallStack = ThreadLocal.withInitial(HashSet::new);
	private static ThreadLocal<Integer> recursionDepth = ThreadLocal.withInitial(() -> 0);
	private static final int MAX_RECURSION_DEPTH = 5000;
	private static final String UNKNOWN_PROPERTY = "-2";

	// ===== 璋冭瘯杈撳嚭寮€鍏?=====
	// 涓?false 鏃跺彧杈撳嚭鏈€缁堢殑 JSON 缁撴灉锛屼笉杈撳嚭浠讳綍璋冭瘯淇℃伅銆?
	// 鍙€氳繃 JVM 鍙傛暟 -Dtchecker.debug=true 寮€鍚皟璇曡緭鍑恒€?
	private static final boolean DEBUG = "true".equalsIgnoreCase(System.getProperty("tchecker.debug"));

	// ===== XSSky 妯″紡寮€鍏?=====
	// 涓?true 鏃剁鐢ㄥ噣鍖栧櫒杩囨护锛氭墍鏈?source-sink 璺緞閮戒細琚姤鍛婏紝
	// 浜ょ粰 XSSky 鐨?PUT fuzzing 杩涜鍔ㄦ€侀獙璇侊紙涓庤鏂囪璁′竴鑷达級銆?
	// 鍙€氳繃 JVM 鍙傛暟 -Dxssky.disableSanitizerFilter=false 鎴?
	// 鐜鍙橀噺 XSSKY_DISABLE_SANITIZER_FILTER=false 鍏抽棴璇ユā寮忥紝鎭㈠鍘熷 TChecker 琛屼负銆?
	public static final boolean DISABLE_SANITIZER_FILTER = resolveDisableSanitizerFilter();

	private static boolean resolveDisableSanitizerFilter() {
		String prop = System.getProperty("xssky.disableSanitizerFilter");
		if (prop == null) {
			String env = System.getenv("XSSKY_DISABLE_SANITIZER_FILTER");
			if (env != null) {
				prop = env;
			}
		}
		// 榛樿鍚敤 XSSky 妯″紡锛堢鐢ㄥ噣鍖栧櫒杩囨护锛?
		if (prop == null) {
			return true;
		}
		return !prop.equalsIgnoreCase("false") && !prop.equals("0");
	}
	
	public StaticAnalysis() {
		init();
		ID2Node = new HashMap<Long, Node>();  // 绉诲埌寰幆澶栵紝鍙垵濮嬪寲涓€娆?
		
		for(Long entry: PHPCGFactory.topFunIds) {
			// ID2Node = new HashMap<Long, Node>();  // 娉ㄩ噴鎺夛紝閬垮厤閲嶇疆
			//the source can only be in the main application
			if(PHPCGFactory.getDir(entry).contains("vendor") ||
					PHPCGFactory.getDir(entry).contains("Test")) {
				continue;
			}
			//the file is included/required, so it is not the entry
			ASTNode filename = ASTUnderConstruction.idToNode.get(entry);
			//System.out.println("filename: "+filename.getEscapedCodeStr());
			if(!PHPCGFactory.entrypoint.contains(filename.getEscapedCodeStr())) {
				//continue;
			}
			if(CSVCFGExporter.cfgSave.get(entry+1)==null) {
				continue;
			}
			Long stmt = CSVCFGExporter.cfgSave.get(entry+1).get(0);
			Set<Long> intro = new HashSet<Long>();
			ID = (long) 0;
			HashMap<String, Long> inter = new HashMap<String, Long>();
			Stack<Long> callStack = new Stack<Long>();
			Node node = new Node(stmt, inter, intro, callStack);
			constructTaintTree(node);
		}
		
		// 鎵€鏈夊叆鍙ｇ偣鍒嗘瀽瀹屽悗锛岀粺涓€杈撳嚭璺緞
		getVulnerablePath();
		// 输出 JSON 格式，与 XSSky PUT_extractor 的 taint_flows JSON 格式一致?
		// 格式: [[source1, ..., sink1], [source2, ..., sink2], ...]
		System.out.println(summaryToJson());
	}

	/**
	 * 灏?sum (HashMap<Long, Stack<Long>>) 杞崲涓?XSSky taint_flows JSON 鏍煎紡銆?
	 * 输出示例: [[169,176], [698,705], [6,13,26]]
	 */
	private String summaryToJson() {
		StringBuilder sb = new StringBuilder();
		sb.append("[\n");
		boolean first = true;
		for(Long key: sum.keySet()) {
			Stack<Long> path = sum.get(key);
			if(path == null || path.isEmpty()) continue;
			if(!first) sb.append(",\n");
			first = false;
			sb.append("  [");
			for(int i = 0; i < path.size(); i++) {
				if(i > 0) sb.append(",");
				sb.append(path.get(i));
			}
			sb.append("]");
		}
		sb.append("\n]");
		return sb.toString();
	}
	
	void init() {
		if(DEBUG) System.out.println("Entry point: "+PHPCGFactory.entrypoint);
		//System.out.println("Call Graph "+PHPCGFactory.call2mtd);
		
		
		//collect cfg node
		cfgNode.addAll(CSVCFGExporter.cfgSave.keySet());
		//set the sanitizer statement
		for(Long astID: PHPCSVEdgeInterpreter.sqlSanitizers) {
			Long stmt = getStatement(astID);
			sqlSanitizers.add(stmt);
		}
		//statement -> source dim
		Set<Long> srcGlobalSet = new HashSet<Long>();
		for(Long dim: PHPCSVEdgeInterpreter.dimVar) {
			Long tmp=null, tmp1=null;
			//get the statement of expression
			ASTNode DIMNode = ASTUnderConstruction.idToNode.get(dim);
			Long stmt = getStatement(dim);
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
			//it is in assignment
			if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight()!=null) {
				Long rightHandId = ((AssignmentExpression) stmtNode).getRight().getNodeId();
				Long leftHandId = ((AssignmentExpression) stmtNode).getLeft().getNodeId();
				//the dim is in the right hand
				if(rightHandId<=dim) {
					tmp=dim;
				}
				//the dim is assigned
				else if(leftHandId.equals(dim)){
					tmp1=dim;
					String iden = getDIMIdentity(DIMNode);
					dstDim.put(stmt, iden);
				}
			}
			//it is a function call
			else if(stmtNode instanceof CallExpressionBase) {
				tmp=dim;
			}
			//the dim is used as source variable
			if(tmp!=null) {
				//the dim is $GLOABLS[] variable
				ASTNode arrayName = ASTUnderConstruction.idToNode.get(dim+2);
				if(arrayName.getProperty("type").equals("string") && arrayName.getEscapedCodeStr().equals("GLOBALS")) {
					srcGlobal.add(stmt, tmp);
					srcGlobalSet.add(tmp);
					Long funcID = stmtNode.getFuncId();
					String iden = getDIMIdentity(ASTUnderConstruction.idToNode.get(dim));
					registerPropertyUse(iden, funcID);
				}
				else {
					srcDim.add(stmt, tmp);
				}
			}
			if(tmp1!=null) {
				//the dim is $GLOABLS[] variable
				ASTNode arrayName = ASTUnderConstruction.idToNode.get(dim+2);
				if(arrayName.getProperty("type").equals("string") && arrayName.getEscapedCodeStr().equals("GLOBALS")) {
					dstGlobal.add(stmt, tmp1);
					Long funcID = stmtNode.getFuncId();
					String iden = getDIMIdentity(ASTUnderConstruction.idToNode.get(dim));
					registerPropertyUse(iden, funcID);
				}
			}
		}
		//statement -> source property
		Set<Long> srcPropSet = new HashSet<Long>();
		for(Long prop: PHPCSVEdgeInterpreter.property) {
			Long stmt = getStatement(prop);
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
			try {
				//it is in assignment
				if(stmtNode instanceof AssignmentExpression) {
					Long rightHandId = ((AssignmentExpression) stmtNode).getRight().getNodeId();
					Long leftHandId = ((AssignmentExpression) stmtNode).getLeft().getNodeId();
					//it is in the right hand
					if(rightHandId<=prop) {
						srcProp.add(stmt, prop);
						srcPropSet.add(prop);
					}
					//it is in the left hand
					else if(leftHandId.equals(prop)){
						dstProp.add(stmt, prop);
					}
					//get the function of prop
					Long funcID = stmtNode.getFuncId();
					String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
					registerPropertyUse(iden, funcID);
				}
				//it is a function call
				else if(stmtNode instanceof CallExpressionBase) {
					srcProp.add(stmt, prop);
					srcPropSet.add(prop);
					Long funcID = stmtNode.getFuncId();
					String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
					registerPropertyUse(iden, funcID);
				}
				//it is a return node
				else if(stmtNode instanceof ReturnStatement) {
					srcProp.add(stmt, prop);
					srcPropSet.add(prop);
					Long funcID = stmtNode.getFuncId();
					String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
					registerPropertyUse(iden, funcID);
				}
			} catch(Exception e){
				//System.err.println("Unknown assignment: "+stmt);
			}
			
		}
		
		//get the sink statement
		for(Long sink: PHPCGFactory.sinks) {
			Long stmt = getStatement(sink);
			sinks.add(stmt);
		}
		//for xss only
		
		for(Long sink: PHPCSVNodeInterpreter.xsssinks) {
			Long stmt = getStatement(sink);
			sinks.add(stmt);
		}
		
		if(DEBUG) System.out.println(sinks);
		
		//get the identity of the source class property and global variables
		for(Long src: srcPropSet) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String iden = getPropIdentity(srcNode, (long) 0);
			name2Stmt.add(iden, src);
		}
		for(Long src: srcGlobalSet) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String iden = getDIMIdentity(srcNode);
			name2Stmt.add(iden, src);
		}
		
		//get all destination stmts
		Set<Long> value = new HashSet<Long>();
		for(Long key: CSVCFGExporter.cfgSave.keySet()) {
			List<Long> vals = CSVCFGExporter.cfgSave.get(key);
			for(Long val: vals) {
				value.add(val);
			}
		}
		
		for(Long key: CSVCFGExporter.cfgSave.keySet()) {
			//catch stmt: the stmt is never reached and it is not the entry point stmt
			if(!value.contains(key) && ASTUnderConstruction.idToNode.containsKey(key)) {
				if(DEBUG) System.out.println("catch: "+key);
				continue;
			}
			
			
			List<Long> vals = CSVCFGExporter.cfgSave.get(key);
			int w = 1;
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(key);
			if(PHPCGFactory.call2mtd.containsKey(key)) {
				w = PHPCGFactory.call2mtd.get(key).size();
			}
			else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
				CallExpressionBase callsite = (CallExpressionBase) ((AssignmentExpression) stmtNode).getRight();
				if(PHPCGFactory.call2mtd.containsKey(callsite.getNodeId())) {
					w = PHPCGFactory.call2mtd.get(callsite.getNodeId()).size();
				}
				
			}
			for(Long val: vals) {
				//expList
				if(ASTUnderConstruction.idToNode.containsKey(key) && ASTUnderConstruction.idToNode.get(key).getProperty("type").equals("AST_EXPR_LIST")) {
					expList.add(val);
				}
				
				//loop back
				if(val<key && ASTUnderConstruction.idToNode.containsKey(val) && CSVCFGExporter.cfgSave.containsKey(val)) {
					//the third element of for loop
					if(CSVCFGExporter.cfgSave.get(val).size()<2) {
						if(CSVCFGExporter.cfgSave.get(val).size()==1) {
							forloop.add(val);
							Long next = CSVCFGExporter.cfgSave.get(val).get(0);
							if(CSVCFGExporter.cfgSave.get(next).size()<2) {
								continue;
							}
							else {
								next = CSVCFGExporter.cfgSave.get(next).get(1);
								if(!Edgesize.containsKey(next)) {
									Edgesize.put(next, w);
								}
								else {
									int number = Edgesize.get(next)+w;
									Edgesize.put(next, number);
								}
							}
						}
						continue;
					}
					//System.err.println("val: "+val);
					loop.add(val);
					Long next = CSVCFGExporter.cfgSave.get(val).get(1);
					while(loop.contains(next)) {
						next = CSVCFGExporter.cfgSave.get(next).get(1);
					}
					if(!Edgesize.containsKey(next)) {
						//System.out.println("edgesize: "+next+" "+w+" "+key);
						Edgesize.put(next, w);
					}
					else {
						int number = Edgesize.get(next)+w;
						//System.out.println("edgesize: "+next+" "+number+" "+key);
						Edgesize.put(next, number);
					}
				}
				else {
					if(!Edgesize.containsKey(val)) {
						Edgesize.put(val, w);
					}
					else {
						int number = Edgesize.get(val)+w;
						Edgesize.put(val, number);
					}
				}
			}
		}
		
		for(Long third: forloop) {
			Edgesize.put(third, 0);
		}
		
		for(Long exp: expList) {
			Edgesize.put(exp, 1);
		}
		
		savesize = (HashMap<Long, Integer>) Edgesize.clone();
		
		// 璁板綍CFG鍓嶉┍鍏崇郴
		if(DEBUG) System.out.println(">>> 寮€濮嬭褰旵FG鍓嶉┍鍏崇郴");
		for(Long key: CSVCFGExporter.cfgSave.keySet()) {
			List<Long> successors = CSVCFGExporter.cfgSave.get(key);
			for(Long successor: successors) {
				// 鍙褰曠涓€涓墠椹憋紙濡傛灉鏈夊涓墠椹憋紝鍚庨潰鐨勪細瑕嗙洊锛?
				if(!cfgPredecessor.containsKey(successor)) {
					cfgPredecessor.put(successor, key);
					if(DEBUG) System.out.println(">>> CFG鍓嶉┍: "+key+" -> "+successor);
				}
			}
		}
		// [debug line removed - encoding issue]
		
		for(Long src: sources) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String dir = PHPCGFactory.getDir(srcNode.getNodeId());
			if(dir.contains("test") || dir.contains("Test")) {
				continue;
			}
			Long stmt = getStatement(src);
			if(stmt == null) {
				continue;
			}
			if(isDirectOutputSource(src, stmt)) {
				directOutputStatements.add(stmt);
			}
			if(isSource(src)) {
				srcStmt.add(stmt, src);
				sourceFunc(src, srcNode.getFuncId());
			}
		}
		
		//get all target functions
		for(Long key: PHPCGFactory.call2mtd.keySet()) {
			allTargets.addAll(PHPCGFactory.call2mtd.get(key));
		}
	}
	
	private void sourceFunc(Long src, Long funcId) {
		//the statement of source
		Long stmtID = getStatement(src);
		//the functions define source
		HashSet<Long> related = getAllcaller(funcId);
		for(Long relate: related) {
			//function => source stmt
			sourceFunc.add(relate, stmtID);
		}
	}

	private void registerPropertyUse(String property, Long function) {
		if (!property.contains("::")) {
			return;
		}
		for (Long caller : getAllcaller(function)) {
			propertiesByFunction.computeIfAbsent(caller, id -> new HashSet<>()).add(property);
		}
	}

	private boolean usesTrackedProperty(Long function, Set<String> trackedProperties) {
		Set<String> properties = propertiesByFunction.get(function);
		if (properties == null) {
			return false;
		}
		for (String tracked : trackedProperties) {
			for (String property : properties) {
				if (check(tracked, property)) {
					if (DEBUG) {
						System.out.println("Property match: " + property + " " + name2Stmt.get(property) + " " + function);
					}
					return true;
				}
			}
		}
		return false;
	}
	
	//get all function called the input function
	private HashSet<Long> getAllcaller(Long func) {
		if(callee2caller.containsKey(func)) {
			HashSet<Long> ret=new HashSet<Long>(callee2caller.get(func));
			return ret;
		}
		else {
			HashSet<Long> ret=new HashSet<Long>();
			Queue<Long> que = new LinkedList<Long>();
			que.add(func);
			while(!que.isEmpty()) {
				Long node = que.poll();
				ret.add(node);
				if(PHPCGFactory.callee2caller.containsKey(node)) {
					List<Long> callers = PHPCGFactory.callee2caller.get(node);
					for(Long caller: callers) {
						ASTNode callerNode = ASTUnderConstruction.idToNode.get(caller);
						//valid call site
						if(callerNode instanceof CallExpressionBase || callerNode instanceof IncludeOrEvalExpression ||
								(callerNode instanceof AssignmentExpression && ((AssignmentExpression) callerNode).getRight() instanceof CallExpressionBase) ||
								(callerNode instanceof ReturnStatement && ((ReturnStatement) callerNode).getReturnExpression() instanceof CallExpressionBase)) {
							Long funcID = callerNode.getFuncId();
							if(!ret.contains(funcID)) {
								//System.out.println("add caller: "+funcID);
								ret.add(funcID);
								que.add(funcID);
							}
						}
					}
				}
			}
			for(Long node: ret) {
				callee2caller.add(func, node);
			}
			return ret;
		}
	}

	//get all callees of the input function
	private HashSet<Long> getAllcallee(Long func) {
		if(caller2callee.containsKey(func)) {
			HashSet<Long> ret=new HashSet<Long>(caller2callee.get(func));
			return ret;
		}
		else {
			HashSet<Long> ret=new HashSet<Long>();
			Queue<Long> que = new LinkedList<Long>();
			que.add(func);
			while(!que.isEmpty()) {
				Long node = que.poll();
				ret.add(node);
				if(PHPCGFactory.mtd2mtd.containsKey(node)) {
					List<Long> callees = PHPCGFactory.mtd2mtd.get(node);
					for(Long callee: callees) {
						ASTNode target = ASTUnderConstruction.idToNode.get(callee);
						if(!ret.contains(callee)) {
							if(PHPCGFactory.getDir(callee).contains("test") ||
									PHPCGFactory.getDir(callee).contains("Test") ||
									PHPCGFactory.getDir(callee).contains("phpunit") ||
									target.getEnclosingClass()!=null && (target.getEnclosingClass().contains("test") || target.getEnclosingClass().contains("Test")) ||
									target.getEscapedCodeStr()!=null && (target.getEscapedCodeStr().contains("test") || target.getEscapedCodeStr().contains("Test"))) {
								continue;
							}
							que.add(callee);
						}
					}
				}
			}
			for(Long node: ret) {
				caller2callee.add(func, node);
			}
			return ret;
		}
	}

	private boolean isDirectOutputSource(Long source, Long stmt) {
		ASTNode output = ASTUnderConstruction.idToNode.get(stmt);
		if(!(output instanceof EchoStatement || output instanceof PrintExpression)) {
			return false;
		}

		// Follow expressions that carry the request value into the output.
		Long child = source;
		while(!stmt.equals(child)) {
			Long parent = PHPCSVEdgeInterpreter.child2parent.get(child);
			if(stmt.equals(parent)) {
				return true;
			}
			ASTNode expression = ASTUnderConstruction.idToNode.get(parent);
			if(expression instanceof ArrayIndexing) {
				Expression array = ((ArrayIndexing) expression).getArrayExpression();
				if(array == null || !child.equals(array.getNodeId())) {
					return false;
				}
			} else if(!(expression instanceof CoalesceExpression || expression instanceof EncapsListExpression
					|| (expression != null && PHPCSVNodeTypes.FLAG_BINARY_CONCAT.equals(expression.getFlags())))) {
				return false;
			}
			child = parent;
		}
		return false;
	}

	//check if the source is a taint variable
	private boolean isSource(Long astId) {
		while(PHPCSVEdgeInterpreter.child2parent.containsKey(astId)) {
			Long save = astId;
			astId = PHPCSVEdgeInterpreter.child2parent.get(astId);
			String rootType = ASTUnderConstruction.idToNode.get(astId).getProperty("type");
			//the source is used in assignment
			if(rootType.equals("AST_ASSIGN") ||
					rootType.equals("AST_ASSIGN_OP") ||
					rootType.equals("AST_ASSIGN_REF") ||
					ASTUnderConstruction.idToNode.get(astId) instanceof CallExpressionBase) {
				// the source is the right value
				if(PHPCSVEdgeInterpreter.parent2child.get(astId).get(1).equals(save)) {
					return true;
				}
				else {
					return false;
				}
			}
		}
		return false;
	}

	private void constructTaintTree(Node node) {
		if(ASTUnderConstruction.idToNode.containsKey(node.astId)) {
			Long funcID = ASTUnderConstruction.idToNode.get(node.astId).getFuncId();
			active.put(funcID, true);
			traverse(node);
			// getVulnerablePath();  // 娉ㄩ噴鎺夛紝鏀逛负鍦ㄦ瀯閫犲嚱鏁颁腑缁熶竴璋冪敤
		}
		
	}

	private void getVulnerablePath() {
		for(Long nodeID: vulStmts.keySet()) {
			if(ID2Node.containsKey(nodeID)) {
				Node vulNode = ID2Node.get(nodeID);
				
				Stack<Long> vulPath = new Stack<Long>();
				vulPath.push(nodeID);
				
				Long currentID = nodeID;
				int maxDepth = 1000;
				int depth = 0;
				Set<Long> visited = new HashSet<Long>();
				visited.add(nodeID);
				
				while(depth < maxDepth && ID2Node.containsKey(currentID)) {
					Node currentNode = ID2Node.get(currentID);
					if(currentNode.parent == null || currentNode.parent == 0) {
						break;
					}
					Long parentID = currentNode.parent;
					if(visited.contains(parentID)) {
						break;
					}
					visited.add(parentID);
					vulPath.push(parentID);
					currentID = parentID;
					depth++;
				}
				
				// Reverse path (source -> sink)
				Stack<Long> reversedPath = new Stack<Long>();
				while(!vulPath.isEmpty()) {
					reversedPath.push(vulPath.pop());
				}
				
				// Remove leading non-source nodes: the path head should be a
				// source statement (in srcStmt). If it is an artificially created
				// predecessor (e.g. sourceExprId-1), strip it so the path starts
				// at the actual source statement as PUT_extractor expects.
				while(reversedPath.size() > 1 && !srcStmt.containsKey(reversedPath.get(0))) {
					reversedPath.remove(0);
				}
				
				sum.put(nodeID, reversedPath);
			} else {
				for(Stack<Long> callstack: vulStmts.get(nodeID)) {
					sum.put(nodeID, callstack);
				}
			}
		}
	}
	
	

	private void DFS(Long nodeID, Stack<Long> vulPath) {
		Node node = ID2Node.get(nodeID);
		if(node.parent==null) {
			Stack<Long> tmp = new Stack<Long>();
			while(vulPath.isEmpty()) {
				tmp.push(vulPath.pop());
			}
			vulPaths.add(tmp);
			return;
		}
		Long prt = node.parent;
		vulPath.add(ID2Node.get(prt).astId);
		DFS(prt, vulPath);
		vulPath.pop();
	}

	private Node mergeNode(Long stmt, Set<Long> intra, HashMap<String, Long> inter, Stack<Long> stack) {
		
		if(ASTUnderConstruction.idToNode.containsKey(stmt)) {
            Long func = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
            // Only skip if function is explicitly inactive AND this is not a return-
            // value propagation (intra is empty). When intra has content, we always
            // merge it to allow taint to flow back from callee to caller.
            if(!active.containsKey(func) || active.get(func)==false) {
                if(intra == null || intra.isEmpty()) {
                    // Function exited and no new taint to merge - skip
                    Node node = ID2Node.get(stmt);
                    // Initialize missing counter without resetting an existing value
                    Edgetimes.putIfAbsent(stmt, 0);
                    return node;
                }
                // Function exited but there IS taint to propagate (return value).
                // Continue with the normal merge and edge-counter update below.
            }
		}
		
		
		Node node = null;
		if(ID2Node.containsKey(stmt)) {
			//merge the intra- and inter- tainted variables
			node = ID2Node.get(stmt);
			node.intro.addAll(intra);
			for(String key: inter.keySet()) {
				node.inter.put(key, inter.get(key));
			}
			node.caller = stack;
		}
		else {
			node = new Node(stmt, inter, intra, stack);
		}
		
		if(!Edgetimes.containsKey(stmt)) {
			Edgetimes.put(stmt, 1);
		}
		else {
			int number = Edgetimes.get(stmt)+1;
			Edgetimes.put(stmt, number);
		}
		
		if(ASTUnderConstruction.idToNode.containsKey(stmt)) {
			Long funcID = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
			Long exit = funcID+2;
			clean.add(exit, stmt);
		}
		//it is file-exit node
		else {
			clean.add(stmt, stmt);
		}
		
		if(DEBUG) System.out.println(stmt+": times: "+Edgetimes.get(stmt)+"size: "+Edgesize.get(stmt));
		
		return node;
	}
	
	private void clean(Node node) {
		node.inter = new HashMap<String, Long>();
		node.intro = new HashSet<Long>();
		node.caller = new Stack<Long>();
		
		Edgetimes.put(node.astId, 0);
	}
	
	//traverse the node's statement
	//@param: one taint node, a boolean value indicating if the current statement is initial source
	//@output: get taint status of this statement, add it to taint tree is it is tainted, and find the next statement ID 
	private boolean traverse(Node node) {
		
		// 娣诲姞绌哄€兼鏌ワ紝闃叉 NullPointerException
		if (node == null) {
			System.err.println("Warning: Encountered null node, skipping...");
			return false;
		}
		
		Long stmt = node.astId;
		if(stmt==null) {
			System.err.println("Fail to get statement location: "+stmt);
			return false;
		}
		
		// 妫€鏌ラ€掑綊娣卞害闄愬埗
		int depth = recursionDepth.get();
		if (depth > MAX_RECURSION_DEPTH) {
			System.err.println("ERROR: Max recursion depth (" + MAX_RECURSION_DEPTH + ") exceeded at node: " + stmt);
			System.err.println("This indicates a potential infinite recursion issue in the CFG.");
			return false;
		}
		
		// 妫€娴嬭皟鐢ㄦ爤涓殑寰幆锛堥槻姝?A->B->C->A 鐨勬棤闄愰€掑綊锛?
		Set<Long> callStack = traverseCallStack.get();
		if (callStack.contains(stmt)) {
			if(DEBUG) System.out.println("INFO: Detected recursion cycle at node " + stmt + ", breaking cycle to prevent stack overflow.");
			return false;
		}
		
		// 灏嗗綋鍓嶈妭鐐瑰姞鍏ヨ皟鐢ㄦ爤
		callStack.add(stmt);
		recursionDepth.set(depth + 1);
		
		try {
			if(DEBUG) System.out.println("parse stmt: "+" "+node.astId+" "+node.inter+" "+node.intro+" "+node.caller);
			//System.out.println("parse stmt: "+node.nodeId+" "+node.astId);
			
			boolean taintFunc = false;
			Node nextNode = null;
			
			//iterate the next statement
			if(CSVCFGExporter.cfgSave.containsKey(stmt)) {
			//the function exits here
			//check if the statement has been sanitized
			boolean valid = isvalid(stmt);
			if(valid && directOutputStatements.contains(stmt) && !sum.containsKey(stmt)) {
				// A single statement is both the source and the sink.
				Stack<Long> path = new Stack<>();
				path.push(stmt);
				sum.put(stmt, path);
			}
			Long topCaller;
			if(node.caller==null || node.caller.isEmpty()) {
				topCaller = (long) 0;
			}
			else {
				topCaller = node.caller.peek();
			}
			
			//check if the statement has data flow relationship with taint variables
			HashMap<Long, Long> related = isrelated(stmt, node.intro, node.inter, topCaller);
			//this statement has been sanitized
			if(!valid) {
				HashMap<String, Long> newInter = null;
				//check weather the node needs to be changed
				Set<String> unrelated = RemoveInterTaint(stmt, topCaller, node.inter);
				//remove unrelated global variables and properties
				if(!unrelated.isEmpty()) {
					newInter = new HashMap<String, Long>();
					for(String key: node.inter.keySet()) {
						if(!unrelated.contains(key)) {
							newInter.put(key, node.inter.get(key));
						}
					}
				}
				//the taint status is not changed
				else {
					newInter = node.inter;
				}
				//iterate the next statement
				//only one subsequent node, just traverse
				Set<Long> intra=node.intro;
				for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
					Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
					Stack<Long> stack =(Stack<Long>) node.caller.clone();
					//update context
					nextNode = mergeNode(next, intra, newInter, stack);
					//merge completed and traverse the next statement
					if(Edgetimes.get(next)==Edgesize.get(next)) {
						//clean(node);
						traverse(nextNode);
					}
					//loop back
					else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
						if(CSVCFGExporter.cfgSave.get(next).size()>1) {
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
						else if(forloop.contains(next)){
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
						else {
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
					}
					else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
						Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
						nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
						if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
							traverse(nextNode);
						}
					}
				}
			}
			//the statement is not sanitized
			else{
				//this stmt is source statement, we add taint variables
				if(srcStmt.containsKey(stmt)) {
					if(DEBUG) System.out.println("source stmt: "+stmt);
					//the source is used in call expression
					List<Long> srcs = srcStmt.get(stmt);
					if(DEBUG) System.out.println(">>> source琛ㄨ揪寮忓垪琛?srcs: "+srcs);
					boolean isarg = true;
					for(Long src: srcs) {
						Long argList = isArg(src, stmt);
						//source is used as argument
						if(argList!=-1) {
							Long func = PHPCSVEdgeInterpreter.child2parent.get(argList);
							String funName = ASTUnderConstruction.idToNode.get(func).getEscapedCodeStr();
							//the function is a sink function
							if(PHPCGFactory.sinks.contains(func)) {
								if(DEBUG) System.out.println("source is used in sink "+node.astId);
								Stack<Long> tmp = (Stack<Long>) node.caller.clone();
								vulStmts.add(node.astId, tmp);
								if(DEBUG) System.out.println("check: "+node.astId+" "+tmp);
								
								// 寤虹珛浠?source 鍒?sink 鐨勮繛鎺?
								if(DEBUG) System.out.println(">>> 鐩存帴 source->sink: stmt="+stmt+" -> sink="+node.astId);
								if(ID2Node.containsKey(stmt)) {
									Node sourceNode = ID2Node.get(stmt);
									addNode(sourceNode, node);
									if(DEBUG) System.out.println(">>> 鎴愬姛杩炴帴鐩存帴璺緞: "+stmt+" -> "+node.astId);
								} else {
									// [debug line removed - encoding issue]
								}
								
								break;
							}
							//the sourcs is santizized
							else {
								if(DEBUG) System.out.println("source is sanitized "+node.astId);
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, node.intro, node.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
							}
						}
						else {
							//add source
							isarg = false;
						}
					}
					
					Set<Long> newIntro = new HashSet<Long>(node.intro);
					Node newNode = node;
					
					if(isarg==false) {
						//node.intro.add(node.astId);
						Set<Long> intra=node.intro;
						HashMap<String, Long> inter = node.inter;
						newNode = addInter(node);
						if(newNode.inter.equals(node.inter)) {
							newIntro.add(node.astId);
						}
						
						// 淇锛氫娇鐢╯ource琛ㄨ揪寮忎綔涓哄墠椹?
						// [debug line removed - encoding issue]
						if(DEBUG) System.out.println(">>> source琛ㄨ揪寮忓垪琛? "+srcs);
						if(DEBUG) System.out.println(">>> source璇彞: "+node.astId);
						
						boolean connected = false;
						for(Long sourceExprId: srcs) {
							// 灏濊瘯浣跨敤sourceExprId-1锛屽洜涓哄疄闄呯殑source琛ㄨ揪寮廔D鍙兘鏄瓙鑺傜偣鐨勫墠涓€涓?
							Long actualSourceId = sourceExprId - 1;
							if(DEBUG) System.out.println(">>> 妫€鏌ource琛ㄨ揪寮? "+sourceExprId+" (灏濊瘯 "+actualSourceId+")");
							
							// 鍏堝皾璇昦ctualSourceId
							if(ID2Node.containsKey(actualSourceId)) {
								Node sourceExprNode = ID2Node.get(actualSourceId);
								addNode(sourceExprNode, node);
								if(DEBUG) System.out.println(">>> 鎴愬姛杩炴帴source琛ㄨ揪寮忓埌璇彞: "+actualSourceId+" -> "+node.astId);
								connected = true;
								break;
							} else if(ID2Node.containsKey(sourceExprId)) {
								// 濡傛灉actualSourceId涓嶅瓨鍦紝灏濊瘯鍘熷ID
								Node sourceExprNode = ID2Node.get(sourceExprId);
								addNode(sourceExprNode, node);
								if(DEBUG) System.out.println(">>> 鎴愬姛杩炴帴source琛ㄨ揪寮忓埌璇彞: "+sourceExprId+" -> "+node.astId);
								connected = true;
								break;
							} else {
								if(DEBUG) System.out.println(">>> source琛ㄨ揪寮?"+actualSourceId+" 鍜?"+sourceExprId+" 閮戒笉鍦↖D2Node涓紝灏濊瘯鍒涘缓");
								// 鍒涘缓actualSourceId鑺傜偣
								Node sourceExprNode = new Node(actualSourceId, new HashMap<>(), new HashSet<>(), node.caller);
								addNode(sourceExprNode, node);
								if(DEBUG) System.out.println(">>> 鍒涘缓骞惰繛鎺ource琛ㄨ揪寮? "+actualSourceId+" -> "+node.astId);
								connected = true;
								break;
							}
						}
						
						if(!connected) {
							// 濡傛灉娌℃湁source琛ㄨ揪寮忥紝fallback鍒癈FG鍓嶉┍
							if(cfgPredecessor.containsKey(stmt) && ID2Node.containsKey(cfgPredecessor.get(stmt))) {
								Long predecessorId = cfgPredecessor.get(stmt);
								Node predecessorNode = ID2Node.get(predecessorId);
								addNode(predecessorNode, node);
								if(DEBUG) System.out.println(">>> Fallback: 杩炴帴CFG鍓嶉┍鍒皊ource: "+predecessorId+" -> "+node.astId);
							} else {
								addNode(root, node);
								if(DEBUG) System.out.println(">>> 璀﹀憡: source鑺傜偣 "+node.astId+" 娌℃湁鎵惧埌鍓嶉┍锛岃繛鎺ュ埌root");
							}
						}
					}
					
					for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
						Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
						Stack<Long> stack =(Stack<Long>) node.caller.clone();
						//update context
						nextNode = mergeNode(next, newIntro, newNode.inter, stack);
						//merge completed and traverse the next statement
						if(Edgetimes.get(next)==Edgesize.get(next)) {
							//clean(node);
							traverse(nextNode);
						}
						//loop back
						else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
							if(CSVCFGExporter.cfgSave.get(next).size()>1) {
								Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
								while(loop.contains(nextnext)) {
									nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
								}
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								//clean(node);
								if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
									traverse(nextNode);
								}
							}
							else if(forloop.contains(next)){
								Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
								while(loop.contains(nextnext)) {
									nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
								}
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								//clean(node);
								if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
									traverse(nextNode);
								}
							}
							else {
								Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
									traverse(nextNode);
								}
							}
						}
						else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
					}
				}
				else{
					//if it reaches sink without sanitization, we save the vulnerable path and return.
					if(DEBUG) System.out.println("related: "+related);
					if(!related.isEmpty() && sinks.contains(stmt)) {
						Stack<Long> tmp = (Stack<Long>) node.caller.clone();
						vulStmts.add(node.astId, tmp);
						if(DEBUG) System.out.println("check: "+node.astId+" "+tmp);
						//link the callee stmts related to return value to the caller
						for(Long taint: related.keySet()) {
							Long source = related.get(taint);
							if(DEBUG) System.out.println(">>> 灏濊瘯杩炴帴: source="+source+" -> sink="+node.astId);
							if(ID2Node.containsKey(source)) {
								Node preNode = ID2Node.get(source);
								addNode(preNode, node);
								if(DEBUG) System.out.println(">>> 鎴愬姛杩炴帴: "+source+" -> "+node.astId);
							} else {
								// [debug line removed - encoding issue]
							}
						}
					}
					
					//the stmt contains a function call
					ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
					//save the caller of the target function
					//this statement is a function call
					if(stmtNode instanceof CallExpressionBase || stmtNode instanceof IncludeOrEvalExpression) {
						Long caller = node.astId;
						Stack<Long> callStack1 = (Stack<Long>) node.caller.clone();
						callStack1.push(caller);
						ArgumentList args = null;
						if(stmtNode instanceof CallExpressionBase) {
							 args = ((CallExpressionBase) stmtNode).getArgumentList();
						}
						//get the target function of this call site
						List<Long> targetFuncs = PHPCGFactory.call2mtd.get(stmt);
						
						//from argument to the related stmt in caller function
						//built-in function
						if(targetFuncs==null || targetFuncs.isEmpty()){
							Set<Long> intra=node.intro;
							HashMap<String, Long> inter = node.inter;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intra, inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==Edgesize.get(next)) {
									//clean(node);
									traverse(nextNode);
								}
								//loop back
								else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
						
						//handle target functions and remove infeaisble ones based on the call contexts
						
						List<Long> validFuncs = new LinkedList<Long>();
						if(targetFuncs.size()>=2) {
							validFuncs = handleFunc(targetFuncs, node.caller, node.astId);
						}
						else {
							validFuncs.add(targetFuncs.get(0));
						}
						
						
						for(Long func: targetFuncs) {
							if(!validFuncs.contains(func)) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, node.intro, node.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							//the callee is also the caller
							boolean contains = false;
							for(Long id: node.caller) {
								if(ID2Node.containsKey(id)) {
									Long astId = ID2Node.get(id).astId;
									Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
									if(callerfunc.equals(func)) {
										contains=true;
										break;
									}
								}
							}
							//already contains, we skip the function
							if(contains==true) {
								Set<Long> intra=node.intro;
								HashMap<String, Long> inter = node.inter;
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							FunctionDef funcNode = (FunctionDef) ASTUnderConstruction.idToNode.get(func);
							//if it is an empty function, we skip the function
							if(funcNode.getContent()==null || funcNode.getContent().size()==0) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Set<Long> intra=node.intro;
									HashMap<String, Long> inter = node.inter;
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							Long funcID = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
							Long exitID = funcID+2;
							
							//check weather params are tainted
							Set<Long> intro = new HashSet<Long>();
							HashMap<Long, Long> param2caller = new HashMap<Long, Long>();
							
							//this is a function call instead of a require statement
							if(args!=null) {
								for(int i=0; i<args.size(); i++) {
									ASTNode arg = args.getArgument(i); 
									for(Long taint: related.keySet()) {
										//the ith argument is tainted
										if(taint.equals(arg.getNodeId())) {
											if(funcNode.getParameterList().size()<=i) {
												continue;
											}
											//the ith parameter will also be tainted
											ParameterBase param = funcNode.getParameterList().getParameter(i);
											intro.add(param.getNodeId());
											param2caller.put(param.getNodeId(), related.get(taint));
										}
									}
								}
							}
							//get next statement in the target function
							Long nextId = (long) -1;
							//the param is not tainted
							if(intro.isEmpty()) {
									boolean flag = usesTrackedProperty(func, node.inter.keySet());
								//the function defines source
								HashSet<Long> src = new HashSet<Long>(node.inter.values());
								//the function defines source statement
								if(sourceFunc.containsKey(func)) {
									HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
									def.removeAll(src);
									//the function defines other source statements
									if(!def.isEmpty()) {
										if(DEBUG) System.out.println("define source: "+func+" "+def);
										flag=true;
									}
									else {
										//System.out.println("not define source: "+func);
									}
								}
								
								Set<Long> intra=node.intro;
								HashMap<String, Long> inter=node.inter;
								
								//step into the function
								if(flag==true && node.caller.size()<20) {
									active.put(func, true);
									if(DEBUG) System.out.println("step into : "+func);
									if(CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1)==null) {
										return false;
									}
									Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
									ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
									nextId = nextstmt.getNodeId();
									nextNode = new Node(nextId, node.inter, intro, callStack1);
									traverse(nextNode);
									
									//the function should exit here
									if(active.get(func)==true) {
										active.put(func, false);
										//it has reaches the exit node
										Node exit=null;
										if(ID2Node.containsKey(func+2)) {
											exit = ID2Node.get(func+2);
										}
										else {
											exit = node;
										}
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											// FIX: propagate taint through function return value
Set<Long> returnIntro = new HashSet<Long>();
if(exit != null && exit.intro != null && !exit.intro.isEmpty()) {
returnIntro.add(stmt);
}
nextNode = mergeNode(next, returnIntro, exit.inter, stack);
											if(Edgetimes.get(next)==Edgesize.get(next)) {
												//clean(node);
												traverse(nextNode);
											}
											//loop back
											else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
												if(CSVCFGExporter.cfgSave.get(next).size()>1) {
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
												else if(forloop.contains(next)){
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
												else {
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
											}
											else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
									}
								}
								//the function is not related, thus we do not step into it
								else {
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										//update context
										nextNode = mergeNode(next, intra, node.inter, stack);
										//merge completed and traverse the next statement
										if(Edgetimes.get(next)==Edgesize.get(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									continue;
								}
							}
							//step into the function
							else {
								active.put(func, true);
								Set<Long> newIntro = new HashSet<Long>();
								Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
								for(Long taintParam: intro) {
									Long prev = param2caller.get(taintParam);
									Node preNode = ID2Node.get(prev);
									nextId = taintParam;
									newIntro.add(nextId);
									nextNode = new Node(nextId, node.inter, newIntro, callStack1);
									addNode(preNode, nextNode);
								}
								traverse(nextNode);
								
								//the target function should exit here
								if(active.get(func)==true) {
									active.put(func, false);
									//it has reaches the exit node
									Node exit=null;
									if(ID2Node.containsKey(func+2)) {
										exit = ID2Node.get(func+2);
									}
									else {
										exit = node;
									}
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										// FIX: propagate taint through function return value
Set<Long> returnIntro = new HashSet<Long>();
if(exit != null && exit.intro != null && !exit.intro.isEmpty()) {
returnIntro.add(stmt);
}
nextNode = mergeNode(next, returnIntro, exit.inter, stack);
										if(Edgetimes.get(next)==Edgesize.get(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
								}
							}	
						}
						
					}
					//the statement's right value is a function call
					else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
						Long caller = node.astId;
						Stack<Long> callStack2 = (Stack<Long>) node.caller.clone();
						callStack2.push(caller);
						CallExpressionBase callsite = (CallExpressionBase) ((AssignmentExpression) stmtNode).getRight();
						ArgumentList args = callsite.getArgumentList();
						//get the target function of this call site
						List<Long> targetFuncs = PHPCGFactory.call2mtd.get(callsite.getNodeId());
						//from argument to the related stmt in caller function
						HashMap<Long, Long> param2caller = new HashMap<Long, Long>();
						//it is built-in function
						if(targetFuncs==null || targetFuncs.isEmpty()) {
							//remove tainted variables
							if(related.keySet().isEmpty()) {
								// Resolve the assigned property in the current function's context.
								Set<String> unrelated = RemoveInterTaint(stmt, topCaller, node.inter);
								HashMap<String, Long> newInter = null;
								//remove unrelated global variables and properties
								if(!unrelated.isEmpty()) {
									newInter = new HashMap<String, Long>();
									for(String key: node.inter.keySet()) {
										if(!unrelated.contains(key)) {
											newInter.put(key, node.inter.get(key));
										}
									}
								}
								//the taint status is not changed
								else {
									newInter = node.inter;
								}
								Set<Long> intra=node.intro;
								
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, newInter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								return false;
							}
							//the tainted variables are used as source in built-in function, we think the destination will also be tainted
							else {
								//update context
								Set<Long> save = new HashSet<Long>(node.intro);
								Node tmp = addInter(node);
								if(tmp.inter.equals(node.inter)) {
									save.add(node.astId);
								}
								Set<Long> save1 = save;
								//link node
								for(Long taint: related.keySet()) {
									Long source = related.get(taint);
									Node preNode = ID2Node.get(source);
									addNode(preNode, node);
								}
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Set<Long> intra=node.intro;
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, save1, tmp.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								return false;
							}
							
						}
						
						List<Long> validFuncs = new LinkedList<Long>();
						if(targetFuncs.size()>=2) {
							validFuncs = handleFunc(targetFuncs, node.caller, node.astId);
						}
						else {
							validFuncs.add(targetFuncs.get(0));
						}
						
						for(Long func: targetFuncs) {
							if(!validFuncs.contains(func)) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, node.intro, node.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							boolean contains = false;
							for(Long id: node.caller) {
								if(ID2Node.containsKey(id)) {
									Long astId = ID2Node.get(id).astId;
									Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
									if(callerfunc.equals(func)) {
										contains=true;
										break;
									}
								}
							}
							//we have already analyzed this function, so we iterate the next stmt
							Set<Long> intra=node.intro;
							HashMap<String, Long> inter = node.inter;
							
							if(contains==true) {
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(ID2Node.get(next));
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							FunctionDef funcNode = (FunctionDef) ASTUnderConstruction.idToNode.get(func);
							if(funcNode.getContent()==null || funcNode.getContent().size()==0) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==Edgesize.get(next)) {
										//clean(node);
										traverse(ID2Node.get(next));
									}
									//loop back
									else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							//check weather params are tainted
							Set<Long> intro = new HashSet<Long>();
							for(int i=0; i<args.size(); i++) {
								ASTNode arg = args.getArgument(i); 
								for(Long taint: related.keySet()) {
									//the ith argument is tainted
									if(taint.equals(arg.getNodeId())) {
										if(funcNode.getParameterList().size()<=i) {
											continue;
										}
										//the ith parameter will also be tainted
										ParameterBase param = funcNode.getParameterList().getParameter(i);
										intro.add(param.getNodeId());
										param2caller.put(param.getNodeId(), related.get(taint));
									}
								}
							}
							
							//get next statement of the target function
							//the param is not tainted
							Long nextId = (long) -1;
							if(intro.isEmpty()) {
								HashMap<String, Long> inter1 = node.inter;
									boolean flag = usesTrackedProperty(func, node.inter.keySet());
								//the function defines source
								HashSet<Long> src = new HashSet<Long>(node.inter.values());
								//the function defines source statement
								if(sourceFunc.containsKey(func)) {
									HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
									def.removeAll(src);
									//the function defines other source statements
									if(!def.isEmpty()) {
										if(DEBUG) System.out.println("define source: "+func+" "+def);
										flag=true;
									}
									else {
										//System.err.println("not define source: "+func);
									}
								}
								
								//the function is related, step into it
								if(flag==true && node.caller.size()<20) {
									active.put(func, true);
									if(DEBUG) System.out.println("step into : "+func);
									Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
									ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
									nextId = nextstmt.getNodeId();
									nextNode = new Node(nextId, inter1, intro, callStack2);
									traverse(nextNode);
									
									//the target function should exit here
									if(active.get(func)==true) {
										active.put(func, false);
										//it has reaches the exit node
										Node exit=null;
										if(ID2Node.containsKey(func+2)) {
											exit = ID2Node.get(func+2);
										}
										else {
											exit = node;
										}
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											// FIX: propagate taint through function return value
Set<Long> returnIntro = new HashSet<Long>();
if(exit != null && exit.intro != null && !exit.intro.isEmpty()) {
returnIntro.add(stmt);
}
nextNode = mergeNode(next, returnIntro, exit.inter, stack);
											if(Edgetimes.get(next)==Edgesize.get(next)) {
												//clean(node);
												traverse(nextNode);
											}
											//loop back
											else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
												if(CSVCFGExporter.cfgSave.get(next).size()>1) {
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
												else if(forloop.contains(next)){
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
												else {
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
											}
											else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
									}
								}
								//the function is not related, we traverse the next statement of caller
								else {
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);

										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										//update context
										nextNode = mergeNode(next, intra, inter1, stack);
										//merge completed and traverse the next statement
										if(Edgetimes.get(next)==Edgesize.get(next)) {
											//clean(node);
											traverse(ID2Node.get(next));
										}
										//loop back
										else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									continue;
								}
							}
							//the parameters are tainted, step into it
							else {
								active.put(func, true);
								Set<Long> newIntro = new HashSet<Long>();
								for(Long taintParam: intro) {
									Long prev = param2caller.get(taintParam);
									Node preNode = ID2Node.get(prev);
									nextId = taintParam;
									newIntro.add(nextId);
									nextNode = new Node(nextId, node.inter, newIntro, callStack2);
									addNode(preNode, nextNode);
								}
								traverse(nextNode);
								
								//the target function should exit here
								if(active.get(func)==true) {
									active.put(func, false);
									//it has reaches the exit node
									Node exit=null;
									if(ID2Node.containsKey(func+2)) {
										exit = ID2Node.get(func+2);
									}
									else {
										exit = node;
									}
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										// FIX: propagate taint through function return value
Set<Long> returnIntro = new HashSet<Long>();
if(exit != null && exit.intro != null && !exit.intro.isEmpty()) {
returnIntro.add(stmt);
}
nextNode = mergeNode(next, returnIntro, exit.inter, stack);
										if(Edgetimes.get(next)==Edgesize.get(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
												traverse(nextNode);
											}
										}
									}
								}
							}
							
						}
					}
					//the statement is a return statement
					else if(stmtNode instanceof ReturnStatement) {
						//the function has exit (because of "return func"
						Long funcId = ASTUnderConstruction.idToNode.get(node.astId).getFuncId();
						if(!(active.containsKey(funcId) && active.get(funcId)==true)) {
							return false;
						}
						
						if(node.caller.isEmpty()) {
							Long nextnext = ASTUnderConstruction.idToNode.get(node.astId).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(node.astId).intro, ID2Node.get(node.astId).inter, ID2Node.get(node.astId).caller);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
							return false;
						}
						Long caller = node.caller.peek();
						Node callerNode = ID2Node.get(caller);
						Long callerID = callerNode.astId;
						//next statement of the caller
						List<Long> nextStmts = CSVCFGExporter.cfgSave.get(callerID);
						HashMap<String, Long> inter = node.inter;
						boolean iscall = false;
						
						ReturnStatement retNode = (ReturnStatement) ASTUnderConstruction.idToNode.get(node.astId);
						ASTNode retValue = retNode.getReturnExpression();
						
						if(retValue instanceof StaticCallExpression || retValue instanceof NewExpression || retValue instanceof MethodCallExpression) {
							Set<Long> validTarget = new HashSet<Long>(); 
							List<Long> validFuncs = new LinkedList<Long>();
							List<Long> funcs = PHPCGFactory.call2mtd.get(retValue.getNodeId());
							if(funcs==null || funcs.isEmpty()){
								iscall = false;
							}
							else {
								iscall = true;
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									int size = Edgesize.get(next);
									Edgesize.put(next, size-1+funcs.size());
								}
								//get valid target functions
								if(funcs.size()>=2) {
									validFuncs = handleFunc(funcs, node.caller, node.astId);
								}
								else {
									validFuncs.add(funcs.get(0));
								}
								
								for(Long func: funcs) {
									if(!validFuncs.contains(func)) {
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											//update context
											nextNode = mergeNode(next, node.intro, inter, stack);
											//merge completed and traverse the next statement
											if(Edgetimes.get(next)==Edgesize.get(next)) {
												//clean(node);
												traverse(ID2Node.get(next));
											}
										}
										continue;
									}
									
									boolean contains = false;
									for(Long id: node.caller) {
										if(ID2Node.containsKey(id)) {
											Long astId = ID2Node.get(id).astId;
											Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
											if(callerfunc.equals(func)) {
												contains=true;
												break;
											}
										}
									}
									if(contains==true) {
										continue;
									}
									boolean flag = usesTrackedProperty(func, node.inter.keySet());
									//the function defines source
									HashSet<Long> src = new HashSet<Long>(node.inter.values());
									//the function defines source statement
									if(sourceFunc.containsKey(func)) {
										HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
										def.removeAll(src);
										//the function defines new source statements
										if(!def.isEmpty()) {
											if(DEBUG) System.out.println("define source: "+func+" "+def);
											flag=true;
										}
										else {
											//System.err.println("not define source: "+func);
										}
									}
									
									//the function is related, we step into it
									if(flag==true) {
										validTarget.add(func);
									}
									//else, go to the exit function
									else {
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											//update context
											nextNode = mergeNode(next, node.intro, inter, stack);
											//merge completed and traverse the next statement
											if(Edgetimes.get(next)==Edgesize.get(next)) {
												//clean(node);
												traverse(ID2Node.get(next));
											}
										}
									}
								}
								
								if(!validTarget.isEmpty()) {
									Set<Long> intra= new HashSet<Long>();
									Stack<Long> callStack3 = (Stack<Long>) node.caller.clone();
									callStack3.push(node.astId);
									
									for(Long func: validTarget) {
										active.put(func, true);
										if(DEBUG) System.out.println("step into : "+func);
										Long nextstmtId = CSVCFGExporter.cfgSave.get(func+1).get(0);
										ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
										Long nextId = nextstmt.getNodeId();
										nextNode = new Node(nextId, node.inter, intra, callStack3);
										traverse(nextNode);
										
										//the target function should exit here
										if(active.get(func)==true) {
											active.put(func, false);
											//it has reaches the exit node
											Node exit=null;
											if(ID2Node.containsKey(func+2)) {
												exit = ID2Node.get(func+2);
											}
											else {
												exit = node;
											}
											for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
												Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
												Stack<Long> stack =(Stack<Long>) node.caller.clone();
												// FIX: propagate taint through function return value
Set<Long> returnIntro = new HashSet<Long>();
if(exit != null && exit.intro != null && !exit.intro.isEmpty()) {
returnIntro.add(stmt);
}
nextNode = mergeNode(next, returnIntro, exit.inter, stack);
												if(Edgetimes.get(next)==Edgesize.get(next)) {
													//clean(node);
													traverse(nextNode);
												}
												//loop back
												else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
													if(CSVCFGExporter.cfgSave.get(next).size()>1) {
														Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
														while(loop.contains(nextnext)) {
															nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
														}
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														//clean(node);
														if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
															traverse(nextNode);
														}
													}
													else if(forloop.contains(next)){
														Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
														while(loop.contains(nextnext)) {
															nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
														}
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														//clean(node);
														if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
															traverse(nextNode);
														}
													}
													else {
														Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
															traverse(nextNode);
														}
													}
												}
												else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
														traverse(nextNode);
													}
												}
											}
										}
									}
								}
							}
						}
						
						
						if(iscall == true) {
							return false;
						}
						
						//if the return value is tainted
						if(!related.keySet().isEmpty()) {
							//update context
							Set<Long> intra=node.intro;
							intra.add((long) (-1));
							//link the callee stmts related to return value to the caller
							for(Long taint: related.keySet()) {
								Long source = related.get(taint);
								Node preNode = ID2Node.get(source);
								addNode(preNode, callerNode);
							}
							//go to the the exit node
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intra, inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==Edgesize.get(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
						//the return value is not tainted
						else {
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, new HashSet<Long>(), inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==Edgesize.get(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
					}
					//the statement is an assignment
					else {
						Long caller;
						if(node.caller.isEmpty()) {
							caller = (long) 0;
						}
						else {
							caller=node.caller.peek();
						}
						
						if(related.keySet().isEmpty()) {
							
							Set<String> unrelated = RemoveInterTaint(stmt, caller, node.inter);
							HashMap<String, Long> newInter = null;
							//remove unrelated global variables and properties
							if(!unrelated.isEmpty()) {
								newInter = new HashMap<String, Long>();
								for(String key: node.inter.keySet()) {
									if(!unrelated.contains(key)) {
										newInter.put(key, node.inter.get(key));
									}
								}
							}
							//the taint status is not changed
							else {
								newInter = node.inter;
							}
							Set<Long> intro = node.intro;
							
							Long stmtId = node.astId;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								if(DEBUG) System.out.println("normal: "+stmt+" "+next);
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intro, newInter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==Edgesize.get(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
										traverse(nextNode);
									}
								}
							}
						}
						else {
							//update context
							Set<Long> save = new HashSet<Long>(node.intro);
							Node tmp = addInter(node);
							if(tmp.inter.equals(node.inter)) {
								save.add(node.astId);
							}
							Set<Long> save1=save;
							//link the callee stmts related to return value to the caller
							for(Long taint: related.keySet()) {
								Long source = related.get(taint);
								Node preNode = ID2Node.get(source);
								addNode(preNode, node);
							}
							//iterate next statement
							Long stmtId = node.astId;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, save, tmp.inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==Edgesize.get(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
										traverse(nextNode);
									}
								}
							}
						}
					}
				}
			}
		}
		//AST Node FUNC_EXIT
		else if(!node.caller.isEmpty()) {
			
			//throw statement, stop here. All normal statements shall exit at FUNC_EXIT
			if(ASTUnderConstruction.idToNode.containsKey(node.astId)) {
				return false;
			}
			
			Edgesize.put(stmt, savesize.get(stmt));
			Long funcID = stmt-2;
			//the function has exited before
			if(active.containsKey(funcID) && active.get(funcID)==false) {
				return false;
			}
			active.put(funcID, false);
			
			//
			if(sourceFunc.containsKey(node.astId-2)) {
				Set<Long> oristmt = new HashSet<Long>(sourceFunc.get(node.astId-2));
				Set<Long> crtstmt = new HashSet<Long>(node.intro);
				for(Long st: node.inter.values()) {
					crtstmt.add(st);
				}
				oristmt.retainAll(crtstmt);
				
				sourceFunc.remove(node.astId-2);
				for(Long st: oristmt) {
					sourceFunc.add(node.astId-2, st);
				}
				
				if(DEBUG) System.out.println("change sourceFunc: "+(node.astId-2)+" "+oristmt);
			}
			
			HashMap<String, Long> inter = node.inter;
			Long caller = node.caller.peek();
			//clean(callerNode);
			if(clean.containsKey(stmt)) {
				if(DEBUG) System.out.println("clean stmt: "+stmt);
				// FIX: Save exit node's intro BEFORE cleaning, because clean list
				// may include the exit node itself, wiping its intro prematurely.
				Set<Long> savedExitIntro = new HashSet<Long>(node.intro);
				for(Long intra: clean.get(stmt)) {
					if(ID2Node.containsKey(intra)) {
						clean(ID2Node.get(intra));
					}
				}
				// Restore the saved intro for return-value taint check below
				node.intro = savedExitIntro;
			}
			if(ID2Node.containsKey(caller)) {
				Node callerNode = ID2Node.get(caller);
				//the function does not change taint status
				
				Long callerID = ID2Node.get(caller).astId;
				List<Long> nextStmts=CSVCFGExporter.cfgSave.get(callerID);
				//next=CSVCFGExporter.cfgSave.get(next).get(0);
				Stack<Long> callStack4 = ID2Node.get(caller).caller;
				Set<Long> intro=ID2Node.get(caller).intro;
				//the return value is tainted
				if(!node.intro.isEmpty() && node.intro.contains((long) -1)){
					intro.add(callerID);
				}
				
				if(callerNode.intro.equals(intro) &&
						callerNode.inter.equals(node.inter)) {
					//unused.add(node.astId-2);
				}
				
				
				for(int i=0; i<CSVCFGExporter.cfgSave.get(callerID).size(); i++) {
					Long next = CSVCFGExporter.cfgSave.get(callerID).get(i);
					Stack<Long> stack = callStack4;
					//update context
					nextNode = mergeNode(next, intro, inter, stack);
					//merge completed and traverse the next statement
					if(Edgetimes.get(next)==Edgesize.get(next)) {
						traverse(ID2Node.get(next));
					}
					//loop back
					else if(Edgetimes.get(next)>Edgesize.get(next) && loop.contains(next)) {
						if(CSVCFGExporter.cfgSave.get(next).size()>1) {
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
						else if(forloop.contains(next)){
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
						else {
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
								traverse(nextNode);
							}
						}
					}
					else if(Edgetimes.get(next)>Edgesize.get(next) && ASTUnderConstruction.idToNode.containsKey(next)){
						Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
						nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
						if(Edgetimes.get(nextnext)==Edgesize.get(nextnext)) {
							traverse(nextNode);
						}
					}
				}
			}
		}
		
		return taintFunc;
		
		} finally {
			// 浠庤皟鐢ㄦ爤涓Щ闄ゅ綋鍓嶈妭鐐癸紝鍏佽鍏朵粬璺緞璁块棶
			callStack.remove(stmt);
			recursionDepth.set(depth);
		}
	}
	

	private Long isArg(Long src, Long stmt) {
		 ASTNode srcNode = null;
		 while(true) {
				//reach the stmt
				if(stmt==src) {
					return (long) -1;
				}
				if(!PHPCSVEdgeInterpreter.child2parent.containsKey(src)) {
					return (long) -1;
				}
				src = PHPCSVEdgeInterpreter.child2parent.get(src);
				srcNode = ASTUnderConstruction.idToNode.get(src);
				if(srcNode instanceof ArgumentList) {
					return src;
				}
				//check if the ast node is a CFG node
			}
	}

	private List<Long> handleFunc(List<Long> targetFuncs, Stack<Long> caller, Long astId) {
		if(DEBUG) System.out.println("Before handle: "+targetFuncs.size());
		Stack<Long> tmp = (Stack<Long>) caller.clone();
		tmp.add(astId);
		Set<String> keywords = new HashSet<String>();
		//get the words used in path
		for(Long c: tmp) {
			Long fileID = toTopLevelFile.getTopLevelId(c);
			String filename = ASTUnderConstruction.idToNode.get(fileID).getEscapedCodeStr();
			String[] words = filename.split("/");
			for(String word: words) {
				word = word.replace(".php", "");
				word = word.toLowerCase();
				word = word.replace("<", "");
				word = word.replace(">", "");
				keywords.add(word);
			}
		}
		
		LinkedList<Long> ret = new LinkedList<Long>();
		MultiHashMap<Integer, Long> map = new MultiHashMap<Integer, Long>();
		int max = -1;
		//get the similarity of path of each target function
		for(Long target: targetFuncs) {
			Long fileID = toTopLevelFile.getTopLevelId(target);
			String filename = ASTUnderConstruction.idToNode.get(fileID).getEscapedCodeStr();
			String[] targetwords = filename.split("/");
			Set<String> targetSet = new HashSet<String>();
			for(String word: targetwords) {
				word = word.replace(".php", "");
				word = word.toLowerCase();
				word = word.replace("<", "");
				word = word.replace(">", "");
				targetSet.add(word);
			}
			targetSet.retainAll(keywords);
			map.add(targetSet.size(), target);
			if(max<targetSet.size()) {
				max = targetSet.size();
			}
		}
		if(DEBUG) System.out.println("after handle: "+map.get(max).size()+" "+map.get(max));
		return map.get(max);
	}

	private boolean isUsed(Long next, Node context, Long caller) {
		ASTNode node = ASTUnderConstruction.idToNode.get(next);
		//we always step into functions
		if(node instanceof CallExpressionBase || (node instanceof AssignmentExpression && ((AssignmentExpression) node).getRight() instanceof CallExpressionBase)) {
			return true;
		}
		else {
			//the next statement does not use taint variable
			if(!dstProp.containsKey(next) && !dstGlobal.containsKey(next) && isrelated(next, context.intro, context.inter, caller).isEmpty()) {
				return false;
			}
			return true;
		}
	}

	//add inter taint to taint status if the stmt is tainted and the left value is inter variable
	/*
	 * param: node under-construct
	 */
	private Node addInter(Node node) {
		Long astId=node.astId;
		Long caller;
		if(node.caller.isEmpty()) {
			caller=(long) 0;
		}
		else {
			caller = node.caller.peek();
		}
		if(!dstProp.containsKey(astId) && !dstGlobal.containsKey(astId)) {
			return node;
		}
		Node ret = new Node(node);
		HashMap<String, Long> newInter = new HashMap<String, Long>(ret.inter); 
		//the statement contains a dst prop
		if(dstProp.containsKey(astId)) {
			List<Long> dstExps = dstProp.get(astId);
			for(Long dst: dstExps) {
				ASTNode dstNode = ASTUnderConstruction.idToNode.get(dst);
				String identity = getPropIdentity(dstNode, caller);
				newInter.put(identity, node.astId);
			}
		}
		//the statement contains a dst Global variable
		if(dstGlobal.containsKey(astId)) {
			List<Long> dstExps = dstGlobal.get(astId);
			for(Long dst: dstExps) {
				ASTNode dstNode = ASTUnderConstruction.idToNode.get(dst);
				String identity = getDIMIdentity(dstNode);
				newInter.put(identity, node.astId);
			}
		}
		ret.inter=newInter;
		return ret;
	}
	
	//add one node to the taint tree
	/*
	 * param: node1 and node2. Set node2 as the children of node1 
	 */
	private void addNode(Node node1, Node node2) {
		node1.children.add(node2);
		node2.parent = node1.astId;  // 璁剧疆鐖惰妭鐐规寚閽?
	}

	//remove inter taints if they are assigned in unrelated statements 
	/*
	 * @param: unrelated statement, caller and inter set of previous node
	 * @return: a set of unrelated global variables and properties 
	 */
	private Set<String> RemoveInterTaint(Long stmt, Long caller, HashMap<String, Long> inter) {
		Set<String> ret = new HashSet<String>();
		//global variable is assigned
		if(dstGlobal.containsKey(stmt)) {
			//location of global expression
			List<Long> dstExps = dstGlobal.get(stmt);
			for(Long exp: dstExps) {
				ASTNode globalNode = ASTUnderConstruction.idToNode.get(exp);
				String globalName = getDIMIdentity(globalNode);
				for(String interTaint: inter.keySet()) {
					if(interTaint.startsWith(globalName) || globalName.startsWith(interTaint)) {
						//inter.remove(interTaint);
						ret.add(interTaint);
					}
				}
			}
		}
		//global property is assigned
		if(dstProp.containsKey(stmt)) {
			//location of prop expression
			List<Long> dstExps = dstProp.get(stmt);
			for(Long exp: dstExps) {
				ASTNode propNode = ASTUnderConstruction.idToNode.get(exp);
				String propName = getPropIdentity(propNode, caller);
				if (UNKNOWN_PROPERTY.equals(propName)) {
					continue;
				}
				for(String interTaint: inter.keySet()) {
					if (!UNKNOWN_PROPERTY.equals(interTaint) && check(propName, interTaint)) {
						ret.add(interTaint);
					}
				}
			}
		}
		return ret;
	}

	/*
	 * @param: one statement
	 * @return: true if the statement is sanitized; otherwise false 
	 */
	private boolean isvalid(Long stmt) {
		// XSSky妯″紡锛氱鐢ㄥ噣鍖栧櫒杩囨护銆?
		// 璁烘枃鏍稿績鎬濇兂鏄笉渚濊禆闈欐€佸噣鍖栧櫒寤烘ā锛屽皢鎵€鏈?source-sink 璺緞
		// 鍏ㄩ儴杈撳嚭锛屼氦缁欏悗缁殑 PUT fuzzing 鍔ㄦ€侀獙璇侊紙閬垮厤鍥犲噣鍖栧櫒寤烘ā
		// 涓嶅叏瀵艰嚧婕忔姤锛屼篃閬垮厤鍥犺鍒ゅ噣鍖栧櫒鏈夋晥瀵艰嚧婕忔帀鍙粫杩囩殑婕忔礊锛夈€?
		if(DISABLE_SANITIZER_FILTER) {
			return true;
		}
		// 鍘熷 TChecker 琛屼负锛氳矾寰勪笂瀛樺湪宸插缓妯＄殑鍑€鍖栧櫒鍒欏垽瀹氫负宸插噣鍖栵紝鍋滄杩借釜銆?
		if(sqlSanitizers.contains(stmt)) {
			return false;
		}
		return true;
	}
	
	/*
	 * @param: the statement ID, the intro set and inter set of previous node, and caller
	 * check if the statement is tainted under the given context
	 * @@return: the taint variable in stmts and and its corresponding related statements  
	 */
	private HashMap<Long, Long> isrelated(Long stmt, Set<Long> intro, HashMap<String, Long> inter, Long caller) {
		HashMap<Long, Long> relatedNodes = new HashMap<Long, Long>();
		
		//check intro-data flow relationship
		for(Long nodeID: intro) {
			Node introNode = ID2Node.get(nodeID);
			if(introNode==null) {
				if(DEBUG) System.out.println("ASTID: "+nodeID);
				continue;
			}
			Long taint = introNode.astId;
			//FIX: Removed taint>stmt check. The original assumption that higher node IDs
			//execute later is incorrect for cross-file and cross-function scenarios.
			//Loop prevention is already handled by traverseCallStack in traverse().
			ASTNode taintNode = ASTUnderConstruction.idToNode.get(taint);
			
			//the dst dim variable is tainted
			if(dstDim.containsKey(taint)) {
				if(srcDim.containsKey(stmt)) {
					List<Long> dims = srcDim.get(stmt);
					for(Long dim: dims) {
						ASTNode srcDimValue = ASTUnderConstruction.idToNode.get(dim);
						String symbol2 = getDIMIdentity(srcDimValue);
						//this srcdim in current statement is related to taint symbol
						if(dstDim.get(taint).startsWith(symbol2) || symbol2.startsWith(dstDim.get(taint))) {
							if(DEBUG) System.out.println("tainted DIM: "+stmt);
							relatedNodes.put(dim, nodeID);
						}
					}
					
					
				}
			}
			
			//check if the statement has intro-data flow relationship with taint variable
			if(DDG.rels.containsKey(taint)) {
				//get all the related statements of the taint
				for(Pair<Long, String> tmp: DDG.rels.get(taint)) {
					//the stmt has deta flow relationship with taint statement
					if(tmp.getL().equals(stmt)) {
						//the taint statement is a assignment
						if(taintNode.getProperty("type").equals("AST_ASSIGN") || taintNode.getProperty("type").equals("AST_ASSIGN_OP") || taintNode.getProperty("type").equals("AST_ASSIGN_REF")) {
							ASTNode leftValue = ((AssignmentExpression) taintNode).getLeft();
							//the symbol in taint statement is an array
							if(leftValue.getProperty("type").equals("AST_DIM")) {
								String symbol1 = getDIMIdentity(leftValue);
								//get the source dim in current stmt
								if(srcDim.containsKey(stmt)) {
									//get the locations of dim expressions in stmt
									List<Long> dims = srcDim.get(stmt);
									for(Long dim: dims) {
										ASTNode rightValue = ASTUnderConstruction.idToNode.get(dim);
										String symbol2 = getDIMIdentity(rightValue);
										//this srcdim in current statement is related to taint symbol
										if(symbol1.startsWith(symbol2) || symbol2.startsWith(symbol1)) {
											relatedNodes.put(dim, nodeID);
										}
									}
								}
							}
							//the taint variable is not an array
							else {
								ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
								if(stmtNode instanceof CallExpressionBase) {
									String tag = tmp.getR();
									ArgumentList args = ((CallExpressionBase) stmtNode).getArgumentList();
									for(int i=0; i<args.size(); i++) {
										ASTNode arg = args.getArgument(i);
										//the taint variable is used as argument 
										if(arg instanceof Variable && ((Variable) arg).getNameExpression().getEscapedCodeStr().equals(tag)) {
											relatedNodes.put(arg.getNodeId(), nodeID);
										}
									}
								}
								else if(stmtNode instanceof EchoStatement) {
									ASTNode target = ((EchoStatement) stmtNode).getEchoExpression();
									relatedNodes.put(target.getNodeId(), nodeID);
								}
								else if(stmtNode instanceof ExitExpression) {
									ASTNode target = ((ExitExpression) stmtNode).getExpression();
									relatedNodes.put(target.getNodeId(), nodeID);
								}
								else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
									String tag = tmp.getR();
									ArgumentList args = ((CallExpressionBase) ((AssignmentExpression) stmtNode).getRight()).getArgumentList();
									for(int i=0; i<args.size(); i++) {
										ASTNode arg = args.getArgument(i);
										//the taint variable is used as argument 
										if(arg instanceof Variable && ((Variable) arg).getNameExpression().getEscapedCodeStr().equals(tag)) {
											relatedNodes.put(arg.getNodeId(), nodeID);
										}
									}
								}
								//
								else if(stmtNode instanceof AssignmentExpression){
									Expression leftNode = ((AssignmentExpression) stmtNode).getLeft();
									if(leftNode instanceof Variable) {
										relatedNodes.put(leftNode.getNodeId(), nodeID);
									}
									
								}
							}
						}
						if(relatedNodes.isEmpty()) {
							relatedNodes.put(stmt, nodeID);
						}
					}
				}
			}
		}
		
		//the stmt contains a source prop
		if(srcProp.containsKey(stmt)) {
			//get the property used in this statement
			List<Long> props = srcProp.get(stmt);
			for(Long propId: props) {
				ASTNode propNode=ASTUnderConstruction.idToNode.get(propId);
				//get the identity of the property
				String srcProp = getPropIdentity(propNode, caller);
				for(String interTaint: inter.keySet()) {
					if(check(srcProp, interTaint)) {
						relatedNodes.put(propId, inter.get(interTaint));
					}
				}
			}
		}
		
		//the stmt is a return statement and it returns a class, we directly get its identity from comments
		if(ASTUnderConstruction.idToNode.get(stmt) instanceof ReturnStatement) {
			//get the function of return statement
			ReturnStatement retNode = (ReturnStatement) ASTUnderConstruction.idToNode.get(stmt);
			Long funcId = retNode.getFuncId();
			//the function returns a class
			if(PHPCGFactory.retCls.containsKey(funcId)) {
				Long classID = PHPCGFactory.retCls.get(funcId);
				String srcProp = classID+"::-1";
				for(String interTaint: inter.keySet()) {
					if(check(srcProp, interTaint)) {
						relatedNodes.put((long) -1, inter.get(interTaint));
					}
				}
			}
		}
		
		//the stmt contains a source global variable
		if(srcGlobal.containsKey(stmt)) {
			List<Long> globals = srcGlobal.get(stmt);
			for(Long globalId: globals) {
				ASTNode globalNode = ASTUnderConstruction.idToNode.get(globalId);
				String srcGlobal = getDIMIdentity(globalNode);
				for(String interTaint: inter.keySet()) {
					if(interTaint.startsWith(srcGlobal) || srcGlobal.startsWith(interTaint)) {
						relatedNodes.put(globalId, inter.get(interTaint));
					}
				}
			}
		}
		
		return relatedNodes;
	}
	
	//check if two properties represent the same variable
	private boolean check(String srcProp, String interTaint) {
		if(srcProp.contains("-1") || interTaint.contains("-1")) {
			srcProp = srcProp.replace("-1", "");
			interTaint = interTaint.replace("-1", "");
			if(srcProp.contains(interTaint) || interTaint.contains(srcProp)) {
				return true;
			}
		}
		else {
			if(srcProp.equals(interTaint)) {
				return true;
			}
		}
		return false;
	}
	
	
	//get the identity of property variable
	/*
	 * @param: propert ast ID, caller
	 * @return: the identity of the property, e.g. astnode(a)::b for $a->b, or UNKNOWN_PROPERTY
	 */
	private String getPropIdentity(ASTNode node, Long caller) {
		if(node instanceof PropertyExpression) {
			String objValue="-1", propValue="*";
			
			//get prop's class
			Expression objNode = ((PropertyExpression) node).getObjectExpression();
			String type = objNode.getProperty("type");
			switch(type) {
			//$this->prop
			case "AST_VAR":
				if(((Variable) objNode).getNameExpression().getEscapedCodeStr()==null) {
					if(DEBUG) System.out.println("2887: "+objNode.getNodeId());
				}
				else if(((Variable) objNode).getNameExpression().getEscapedCodeStr().equals("this")) {
					objValue = objNode.getEnclosingClass();
					String namespace = objNode.getEnclosingNamespace();
					objValue = PHPCGFactory.getClassId(objValue, objNode.getNodeId(), namespace).toString();
				}
				break;
			//func()->prop
			case "AST_CALL":
			case "AST_METHOD_CALL":
			case "AST_STATIC_CALL":
				if(PHPCGFactory.call2mtd.containsKey(objNode.getNodeId())) {
					Long targetFuncID = PHPCGFactory.call2mtd.get(objNode.getNodeId()).get(0);
					if(PHPCGFactory.retCls.containsKey(targetFuncID)){
						objValue = PHPCGFactory.retCls.get(targetFuncID).toString(); 
					}
				}
				break;
			
			}
			//we do not know the objValue yet, thus we parse its value
			if(objValue.equals("-1")) {
				ParseVar parsevar = new ParseVar();
				parsevar.init(1, false, "");
				String className = parsevar.IntroDataflow(objNode.getNodeId()).iterator().next();
				if(className.startsWith("$")) {
					try {
						//the class is returned from a known target function
						Long classId = Long.parseLong(className.substring(1, className.length() - 1));
						ASTNode classNode = ASTUnderConstruction.idToNode.get(classId);
						if(classNode instanceof CallExpressionBase) {
							if(PHPCGFactory.call2mtd.containsKey(classNode.getNodeId())) {
								Long targetFuncID = PHPCGFactory.call2mtd.get(classNode.getNodeId()).get(0);
								if(PHPCGFactory.retCls.containsKey(targetFuncID)){
									objValue = PHPCGFactory.retCls.get(targetFuncID).toString(); 
								}
							}
						}
					}catch(Exception e) {
						
					}
				}
				else {
					objValue = className;
				}
				
			}
			
			//get prop's name
			Expression propNode = ((PropertyExpression) node).getPropertyExpression();
			//the prop name is an identifier
			if(propNode.getProperty("type").equals("string")) {
				propValue = propNode.getEscapedCodeStr();
			}
			//the prop name is a variable and it is assigned by the parameter
			else if (propNode instanceof Variable && caller != 0L) {
				ASTNode callerNode = ASTUnderConstruction.idToNode.get(caller);
				if (callerNode instanceof AssignmentExpression) {
					callerNode = ((AssignmentExpression) callerNode).getRight();
				} else if (callerNode instanceof ReturnStatement) {
					callerNode = ((ReturnStatement) callerNode).getReturnExpression();
				}
				ASTNode function = ASTUnderConstruction.idToNode.get(propNode.getFuncId());
				if (!(callerNode instanceof CallExpressionBase) || !(function instanceof FunctionDef)) {
					return UNKNOWN_PROPERTY;
				}
				ArgumentList arguments = ((CallExpressionBase) callerNode).getArgumentList();
				ParameterList parameters = ((FunctionDef) function).getParameterList();
				if (arguments == null || parameters == null) {
					return UNKNOWN_PROPERTY;
				}
				String varName = ((Variable) propNode).getNameExpression().getEscapedCodeStr();
				for (int i = 0; i < Math.min(parameters.size(), arguments.size()); i++) {
					if (parameters.getParameter(i).getName().equals(varName)) {
						Expression argument = arguments.getArgument(i);
						if ("string".equals(argument.getProperty("type"))) {
							propValue = argument.getEscapedCodeStr();
						}
						break;
					}
				}
			}
			
			//we at least know the prop name
			if(!propValue.equals("*")) {
				return objValue+"::"+propValue;
			}
		}
		return UNKNOWN_PROPERTY;
	}
	
	//get the identity of DIM variable
	/*
	 * @param: node($a[b][c])
	 * @return a$b$c
	 */
	public String getDIMIdentity(ASTNode node) {
		//$a[b][c], we do not return $a or $a[b], instead we only return $a[b][c]
		if(PHPCSVEdgeInterpreter.child2parent.containsKey(node.getNodeId())) {
			//the the parent of DIM variable
			ASTNode parent = ASTUnderConstruction.idToNode.get(PHPCSVEdgeInterpreter.child2parent.get(node.getNodeId()));
			//DIM's parent is a a DIM variable
			if(parent instanceof ArrayIndexing) {
				return "-1";
			}
		}
		while(node instanceof ArrayIndexing) {
			node = ((ArrayIndexing) node).getArrayExpression();
		}
		//AST_DIM. AST_VAR, AST_NAME
		Long constantId = node.getNodeId()+2;
		String identity="";
		while(true) {
			if(!ASTUnderConstruction.idToNode.containsKey(constantId)) {
				return "-1";
			}
			ASTNode constant = ASTUnderConstruction.idToNode.get(constantId);
			if(constant.getEscapedCodeStr()==null || constant.getEscapedCodeStr().isEmpty()) {
				break;
			}
			identity = identity+constant.getEscapedCodeStr()+"$";
			constantId = constantId+1;
		}
		//fail to get DIM identity
		if(identity.equals("")) {
			return "-1";
		}
		return identity;
	} 

	//get the statement of taint node
	/*
	 * @param: astID
	 * @return: <statement, stmtList>
	 */
	private Long getStatement(Long astId) {
		while(true) {
			//check if astId is cfg node
			if(cfgNode.contains(astId)) {
				return astId;
			}
			//get astId's parent
			if(!PHPCSVEdgeInterpreter.child2parent.containsKey(astId)) {
				return null;
			}
			astId = PHPCSVEdgeInterpreter.child2parent.get(astId);
			//check if the ast node is a CFG node
		}
	}
}







