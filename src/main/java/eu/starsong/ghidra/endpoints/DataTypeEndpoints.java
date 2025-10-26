package eu.starsong.ghidra.endpoints;
import eu.starsong.ghidra.util.TransactionHelper;
import eu.starsong.ghidra.util.TransactionHelper.TransactionException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class DataTypeEndpoints extends AbstractEndpoint {

    private PluginTool tool;
    
    // Updated constructor to accept port
    public DataTypeEndpoints(Program program, int port) {
        super(program, port); // Call super constructor
    }
    
    public DataTypeEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        // server.createContext("/datatypes", this::handleDataTypes);
        server.createContext("/datatypes/add", this::handleAddDataTypes);
        // server.createContext("/datatypes/delete", this::handleDeleteDataTypes);
    }
    
    /**
     * Build a map containing information about a DataType
     */
    private Map<String, Object> buildDataTypeInfo(DataType dataType) {
        Map<String, Object> info = new HashMap<>();
        
        info.put("name", dataType.getName());
        info.put("displayName", dataType.getDisplayName());
        info.put("id", dataType.getUniversalID().toString());
        info.put("length", dataType.getLength());
        info.put("description", dataType.getDescription());
        info.put("categoryPath", dataType.getCategoryPath().toString());
        info.put("pathName", dataType.getPathName());
        info.put("mnemonic", dataType.getMnemonic(null));
        
        // Add type classification
        info.put("isStruct", dataType instanceof ghidra.program.model.data.Structure);
        info.put("isBuiltIn", dataType instanceof ghidra.program.model.data.BuiltInDataType);
        info.put("isComposite", dataType instanceof ghidra.program.model.data.Composite);
        info.put("isEnum", dataType instanceof ghidra.program.model.data.Enum);
        info.put("isPointer", dataType instanceof ghidra.program.model.data.Pointer);
        info.put("isUnion", dataType instanceof ghidra.program.model.data.Union);
        info.put("isTypeDef", dataType instanceof ghidra.program.model.data.TypeDef);
        info.put("isArray", dataType instanceof ghidra.program.model.data.Array);
        info.put("isDynamic", dataType instanceof ghidra.program.model.data.Dynamic);
        info.put("isFunctionDef", dataType instanceof ghidra.program.model.data.FunctionDefinition);
        
        // Add HATEOAS links
        Map<String, Object> links = new HashMap<>();
        Map<String, String> selfLink = new HashMap<>();
        selfLink.put("href", "/datatypes/path/" + dataType.getPathName().replace("/", "%2F"));
        selfLink.put("href", "/datatypes//id/" + dataType.getUniversalID().toString());
        links.put("self", selfLink);
        info.put("_links", links);
        
        return info;
    }

    /**
     * Handle GET /datatypes - List all datatypes or get specific one by name
     */
    // private void handleDataTypes(HttpExchange exchange) throws IOException {
    //     if (!"GET".equals(exchange.getRequestMethod())) {
    //         sendErrorResponse(exchange, 405, "Method not allowed");
    //         return;
    //     }

    //     try {
    //         String query = exchange.getRequestURI().getQuery();
    //         String name = null;
            
    //         if (query != null) {
    //             String[] params = query.split("&");
    //             for (String param : params) {
    //                 String[] keyValue = param.split("=");
    //                 if (keyValue.length == 2 && "name".equals(keyValue[0])) {
    //                     name = java.net.URLDecoder.decode(keyValue[1], "UTF-8");
    //                     break;
    //                 }
    //             }
    //         }

    //         DataTypeManager dtm = program.getDataTypeManager();
    //         Map<String, Object> response = new HashMap<>();

    //         if (name != null) {
    //             // Get specific datatype by name
    //             DataType dataType = dtm.getDataType(name);
    //             if (dataType == null) {
    //                 sendErrorResponse(exchange, 404, "DataType not found: " + name);
    //                 return;
    //             }
    //             response = buildDataTypeInfo(dataType);
    //         } else {
    //             // List all datatypes
    //             List<Map<String, Object>> datatypes = new ArrayList<>();
    //             Iterator<DataType> iterator = dtm.getAllDataTypes();
                
    //             while (iterator.hasNext()) {
    //                 DataType dt = iterator.next();
    //                 datatypes.add(buildDataTypeInfo(dt));
    //             }
                
    //             response.put("datatypes", datatypes);
    //             response.put("count", datatypes.size());
    //         }

    //         sendJsonResponse(exchange, 200, response);
            
    //     } catch (Exception e) {
    //         Msg.error(this, "Error handling datatypes request", e);
    //         sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
    //     }
    // }

    /**
     * Handle POST /datatypes/add - Add new datatype from C-parsed string
     */
    private void handleAddDataTypes(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        try {
            Map<String, String> params = parseJsonPostParams(exchange);

            // Debug - log all parameters received by this method
            StringBuilder debugInfo = new StringBuilder("DEBUG handleAddDataTypes - Received parameters: ");
            for (Map.Entry<String, String> entry : params.entrySet()) {
                debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
            }
            Msg.info(this, debugInfo.toString());

            String cDataTypeStr = params.get("cDataType");
            String categoryPathStr = params.get("categoryPath");

            Msg.info(this, "handleAddDataTypes - extracted parameters: cDataType=" + cDataTypeStr + 
                           ", categoryPath=" + categoryPathStr);

            if (cDataTypeStr == null || cDataTypeStr.trim().isEmpty()) {
                Msg.info(this, "handleAddDataTypes - Missing required parameter: cDataType");
                sendErrorResponse(exchange, 400, "Missing required field: cDataType", "MISSING_PARAMETER");
                return;
            }

            CategoryPath categoryPath = (categoryPathStr != null && !categoryPathStr.trim().isEmpty())
                    ? new CategoryPath(categoryPathStr)
                    : CategoryPath.ROOT;
    
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                return;
            }
            
            DataTypeManager dtm = program.getDataTypeManager();
            CParser cParser = new CParser(dtm);

            // Parse the C DataType string
            DataType parsedDataType;
            try {
                parsedDataType = cParser.parse(cDataTypeStr);
            } catch (ParseException e) {
                Msg.error(this, "Parsing C type string failed: Add DataType", e);
                sendErrorResponse(exchange, 400, "Failed to parse C DataType string: " + e.getMessage(), "INVALID_C_DATATYPE");
                return;
            }

            if (parsedDataType == null) {
                Msg.error(this, "Parsed DataType is null");
                sendErrorResponse(exchange, 400, "No data type provided in the C string", "INVALID_C_DATATYPE");
                return;
            }

            Msg.info(this, "Successfully parsed C DataType: " + parsedDataType.getName());

            // Start transaction

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("cDataType", cDataTypeStr);
            resultMap.put("categoryPath", categoryPath.toString());

            AtomicReference<DataType> refAddedDataType = new AtomicReference<>();

            Exception ret;

            try {

                ret = TransactionHelper.executeInTransaction(program, "Add DataType", () -> {
                    dtm.createCategory(categoryPath);

                    // Add the DataType to the manager
                    DataType addedDataType;
                    try {
                        addedDataType = dtm.addDataType(parsedDataType, DataTypeConflictHandler.DEFAULT_HANDLER);
                    }catch (Exception e) {
                        Msg.error(this, "Error creating category path: " + categoryPath +  e);
                        return e;
                    }
                    
                    addedDataType.setCategoryPath(categoryPath);

                    Msg.info(this, "Successfully added DataType " + parsedDataType.getName() + " under the name: " + addedDataType.getName() + " on path: " + addedDataType.getPathName());
                    
                    refAddedDataType.set(addedDataType);
                    return null;
                });

            } catch (TransactionException e) {
                Msg.error(this, "Transaction failed: Add DataType", e);
                sendErrorResponse(exchange, 500, "Failed to add DataType: " + e.getMessage(), "TRANSACTION_ERROR");
                return;
            }

           if (ret instanceof DuplicateNameException) {
                Msg.error(this, "Duplicate DataType name error");
                sendErrorResponse(exchange, 400, "DataType with the same name already exists: " + parsedDataType.getName(), "DUPLICATE_DATATYPE");
                return;
           } else if (ret != null) {
                Msg.error(this, "Unknown error adding DataType", ret);
                sendErrorResponse(exchange, 500, "Error adding DataType: " + ret.getMessage(), "INTERNAL_ERROR");
                return;
           }

            resultMap.put("message", "DataType added successfully under transaction");

            Map<String, Object> dataTypeInfo = buildDataTypeInfo(refAddedDataType.get());
            resultMap.put("addedDataType", dataTypeInfo);

            resultMap.put("addedDataType", buildDataTypeInfo(refAddedDataType.get()));
            
            // Build HATEOAS response
            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(resultMap);

            builder.addLink("self", "/datatypes/path/" + refAddedDataType.get().getPathName().replace("/", "%2F"));
            builder.addLink("self", "/datatypes/id/" + refAddedDataType.get().getUniversalID().toString());
            builder.addLink("datatypes", "/datatypes");
            builder.addLink("program", "/program");
            
            sendJsonResponse(exchange, builder.build(), 201);
            return;

            
        } catch (IOException e) {
            Msg.error(this, "Error parsing POST params for data type addition", e);
            sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST");
        } catch (Exception e) {
            Msg.error(this, "Unexpected error adding data type", e);
            sendErrorResponse(exchange, 500, "Error adding data type: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle DELETE /datatypes/delete - Delete datatype by name
     */
    // private void handleDeleteDataTypes(HttpExchange exchange) throws IOException {
    //     if (!"DELETE".equals(exchange.getRequestMethod())) {
    //         sendErrorResponse(exchange, 405, "Method not allowed");
    //         return;
    //     }

    //     try {
    //         Map<String, Object> requestData = parseJsonRequest(exchange);
            
    //         String name = (String) requestData.get("name");
    //         if (name == null || name.trim().isEmpty()) {
    //             sendErrorResponse(exchange, 400, "Missing required field: name");
    //             return;
    //         }

    //         DataTypeManager dtm = program.getDataTypeManager();
    //         DataType dataType = dtm.getDataType(name);
            
    //         if (dataType == null) {
    //             sendErrorResponse(exchange, 404, "DataType not found: " + name);
    //             return;
    //         }
            
    //         // Check if datatype is in use
    //         if (dataType.isDeleted()) {
    //             sendErrorResponse(exchange, 400, "DataType is already deleted: " + name);
    //             return;
    //         }

    //         // Start transaction
    //         int transactionID = program.startTransaction("Delete DataType");
    //         try {
    //             boolean success = dtm.remove(dataType, null);
                
    //             Map<String, Object> response = new HashMap<>();
    //             if (success) {
    //                 response.put("success", true);
    //                 response.put("message", "DataType deleted successfully: " + name);
    //                 sendJsonResponse(exchange, 200, response);
    //             } else {
    //                 response.put("success", false);
    //                 response.put("message", "Failed to delete DataType (may be in use): " + name);
    //                 sendJsonResponse(exchange, 400, response);
    //             }
                
    //         } finally {
    //             program.endTransaction(transactionID, true);
    //         }
            
    //     } catch (Exception e) {
    //         Msg.error(this, "Error deleting datatype", e);
    //         sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
    //     }
    // }
}