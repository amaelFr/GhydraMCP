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
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.data.Enum;

import java.io.IOException;
import java.io.StringWriter;
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

        server.createContext("/datatypes/by-path/", this::handleDataTypeByPath);
        server.createContext("/datatypes/by-name/", this::handleDataTypeByName);
        server.createContext("/datatypes/by-id/", this::handleDataTypeById);
        server.createContext("/datatypes", this::handleDataTypes);
        // server.createContext("/datatypes/delete", this::handleDeleteDataTypes);
    }

    /**
     * Build a map containing information about a DataType
     * @throws CancelledException
     */
    private Map<String, Object> buildDataTypeInfo(DataType dataType) throws CancelledException {
        Map<String, Object> info = new HashMap<>();

        info.put("name", dataType.getName());
        info.put("displayName", dataType.getDisplayName());

        // Check if UniversalID is not null before converting to string
        UniversalID universalId = dataType.getUniversalID();
        info.put("id", universalId != null ? universalId.toString() : null);

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

        StringWriter sWritter = new StringWriter();

        AnnotationHandler annotationHandler = new DefaultAnnotationHandler();
        DataTypeWriter dataTypeWriter;
        try {
            dataTypeWriter = new DataTypeWriter(getCurrentProgram().getDataTypeManager(), sWritter, annotationHandler);
            List<DataType> types = new ArrayList<>();
			types.add(dataType);
			dataTypeWriter.write(types, new ConsoleTaskMonitor(), true);

            info.put("C_dataType", sWritter.toString());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        // Add HATEOAS links
        Map<String, Object> links = new HashMap<>();
        Map<String, String> selfLink = new HashMap<>();
        selfLink.put("href", "/datatypes/by-path/" + dataType.getPathName().replace("/", "%2F"));
        if (universalId != null) {
            selfLink.put("href", "/datatypes/by-id/" + universalId.toString());
        }
        selfLink.put("href", "/datatypes/by-name/" + dataType.getName());
        links.put("self", selfLink);
        info.put("_links", links);

        return info;
    }

    /**
     * Handle GET /datatypes - List all datatypes with filtering and pagination
     * Handle POST /datatypes - Create a new datatype
     */
    private void handleDataTypes(HttpExchange exchange) throws IOException {
        try {
            // Always check for program availability first
            Program program = getCurrentProgram();
            if (program == null) {
                sendErrorResponse(exchange, 503, "No program is currently loaded", "NO_PROGRAM_LOADED");
                return;
            }

            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);

                String nameContains = params.get("name_contains");
                String nameRegexFilter = params.get("name_matches_regex");
                String descriptionContains = params.get("description_contains");
                String descriptionRegexFilter = params.get("description_matches_regex");
                String categoryContains = params.get("category_contains");
                String categoryRegexFilter = params.get("category_matches_regex");

                String categoryFilter = params.get("category");
                String typeFilter = params.get("type"); // struct, enum, pointer, etc.
                boolean excludePointers = "true".equalsIgnoreCase(params.get("exclude_pointers"));

                List<Map<String, Object>> datatypes = new ArrayList<>();
                DataTypeManager dtm = program.getDataTypeManager();

                // First pass: collect all base data types (non-pointers)
                Set<String> baseTypeNames = new HashSet<>();
                if (excludePointers) {
                    Iterator<DataType> preIterator = dtm.getAllDataTypes();
                    while (preIterator.hasNext()) {
                        DataType dt = preIterator.next();
                        if (!(dt instanceof Pointer)) {
                            baseTypeNames.add(dt.getName());
                        }
                    }
                }

                // Get all datatypes
                Iterator<DataType> iterator = dtm.getAllDataTypes();
                while (iterator.hasNext()) {
                    DataType dt = iterator.next();

                    // Skip pointers if their base type exists and exclude_pointers is enabled
                    if (excludePointers && dt instanceof Pointer) {
                        Pointer ptr = (Pointer) dt;
                        DataType baseType = ptr.getDataType();
                        if (baseType != null && baseTypeNames.contains(baseType.getName())) {
                            continue; // Skip this pointer type
                        }
                    }

                    // Apply name filters
                    if (nameContains != null) {
                        if (!dt.getName().toLowerCase().contains(nameContains.toLowerCase())) {
                            continue;
                        }
                    }

                    if (nameRegexFilter != null &&
                        !dt.getName().matches(nameRegexFilter)) {
                            continue;
                    }

                    // Apply description filters
                    if (descriptionContains != null || descriptionRegexFilter != null) {
                        String desc = dt.getDescription();
                        if (desc == null){
                            continue;
                        }
                        if (descriptionRegexFilter != null && !desc.matches(descriptionRegexFilter)
                            || descriptionContains != null && !desc.toLowerCase().contains(descriptionContains.toLowerCase())) {
                            continue;
                        }
                    }

                    // Apply category filters
                    if (categoryContains != null) {
                        if (!dt.getCategoryPath().toString().toLowerCase().contains(categoryContains.toLowerCase())) {
                            continue;
                        }
                    }

                    if (categoryRegexFilter != null && !dt.getCategoryPath().toString().matches(categoryRegexFilter)) {
                        continue;
                    }

                    if (categoryFilter != null && !dt.getCategoryPath().toString().equals(categoryFilter)) {
                        continue;
                    }

                    // Apply type filter
                    if (typeFilter != null) {
                        boolean matchesType = false;
                        switch (typeFilter.toLowerCase()) {
                            case "struct":
                                matchesType = dt instanceof Structure;
                                break;
                            case "enum":
                                matchesType = dt instanceof Enum;
                                break;
                            case "pointer":
                                matchesType = dt instanceof Pointer;
                                break;
                            case "union":
                                matchesType = dt instanceof Union;
                                break;
                            case "typedef":
                                matchesType = dt instanceof TypeDef;
                                break;
                            case "array":
                                matchesType = dt instanceof Array;
                                break;
                            case "function":
                                matchesType = dt instanceof FunctionDefinition;
                                break;
                            case "builtin":
                                matchesType = dt instanceof BuiltInDataType;
                                break;
                        }
                        if (!matchesType) {
                            continue;
                        }
                    }
                    datatypes.add(buildDataTypeInfo(dt));
                }

                // Apply pagination
                int endIndex = Math.min(datatypes.size(), offset + limit);
                List<Map<String, Object>> paginatedDataTypes = offset < datatypes.size()
                    ? datatypes.subList(offset, endIndex)
                    : new ArrayList<>();

                // Build response with pagination links
                eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                    .success(true)
                    .result(paginatedDataTypes);

                // Add pagination metadata
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("size", datatypes.size());
                metadata.put("offset", offset);
                metadata.put("limit", limit);
                builder.metadata(metadata);

                // Add HATEOAS links with all filter parameters
                StringBuilder queryString = new StringBuilder("?offset=" + offset + "&limit=" + limit);
                if (nameContains != null) queryString.append("&name_contains=").append(nameContains);
                if (nameRegexFilter != null) queryString.append("&name_matches_regex=").append(nameRegexFilter);
                if (descriptionContains != null) queryString.append("&description_contains=").append(descriptionContains);
                if (descriptionRegexFilter != null) queryString.append("&description_matches_regex=").append(descriptionRegexFilter);
                if (categoryContains != null) queryString.append("&category_contains=").append(categoryContains);
                if (categoryRegexFilter != null) queryString.append("&category_matches_regex=").append(categoryRegexFilter);
                if (categoryFilter != null) queryString.append("&category=").append(categoryFilter);
                if (typeFilter != null) queryString.append("&type=").append(typeFilter);
                queryString.append("&exclude_pointers="+excludePointers);

                System.out.println("Generated query string: " + queryString.toString());
                Msg.info(this, "Generated query string: " + queryString.toString());

                builder.addLink("self", "/datatypes" + queryString.toString());

                // Add next/prev links if applicable
                if (endIndex < datatypes.size()) {
                    builder.addLink("next", "/datatypes?offset=" + endIndex + "&limit=" + limit);
                }

                if (offset > 0) {
                    int prevOffset = Math.max(0, offset - limit);
                    builder.addLink("prev", "/datatypes?offset=" + prevOffset + "&limit=" + limit);
                }

                sendJsonResponse(exchange, builder.build(), 200);
            } else if ("POST".equals(exchange.getRequestMethod()) || "PUT".equals(exchange.getRequestMethod())) {
                // Redirect to add endpoint
                handleCreateUpdateDataType(exchange);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error handling /datatypes endpoint", e);
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle GET /datatypes/by-path/{path} - Get datatype by path name
     */
    private void handleDataTypeByPath(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
            return;
        }
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
            return;
        }

        try {
            String path = exchange.getRequestURI().getPath();
            String pathName = path.substring("/datatypes/by-path/".length());
            pathName = java.net.URLDecoder.decode(pathName, "UTF-8");

            if (pathName.isEmpty()) {
                sendErrorResponse(exchange, 400, "Path name is required", "MISSING_PARAMETER");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dtm.getDataType(pathName);

            if (dataType == null) {
                sendErrorResponse(exchange, 404, "DataType not found at path: " + pathName, "DATATYPE_NOT_FOUND");
                return;
            }

            Map<String, Object> dataTypeInfo = buildDataTypeInfo(dataType);

            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(dataTypeInfo);

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error retrieving datatype by path", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle GET /datatypes/by-name/{name} - Get datatype by name
     */
    private void handleDataTypeByName(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
            return;
        }
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
            return;
        }

        try {
            String path = exchange.getRequestURI().getPath();
            String name = path.substring("/datatypes/by-name/".length());
            name = java.net.URLDecoder.decode(name, "UTF-8");

            if (name.isEmpty()) {
                sendErrorResponse(exchange, 400, "Name is required", "MISSING_PARAMETER");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            List<DataType> dataTypes = new ArrayList<>();

            // Find all datatypes with matching name (there can be multiple with same name in different categories)

            Iterator<DataType> iterator = dtm.getAllDataTypes();
            while (iterator.hasNext()) {
                DataType dt = iterator.next();
                if (dt.getName().equals(name)) {
                    dataTypes.add(dt);
                }
            }

            if (dataTypes.isEmpty()) {
                sendErrorResponse(exchange, 404, "DataType not found with name: " + name, "DATATYPE_NOT_FOUND");
                return;
            }

            Map<String, Object> response = new HashMap<>();
            if (dataTypes.size() == 1) {
                response = buildDataTypeInfo(dataTypes.get(0));
            } else {
                // Multiple datatypes with same name
                List<Map<String, Object>> dataTypesList = new ArrayList<>();
                for (DataType dt : dataTypes) {
                    dataTypesList.add(buildDataTypeInfo(dt));
                }
                response.put("datatypes", dataTypesList);
                response.put("count", dataTypesList.size());
                response.put("message", "Multiple datatypes found with name: " + name);
            }

            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(response);

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error retrieving datatype by name", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle GET /datatypes/by-id/{universalId} - Get datatype by universal ID
     */
    private void handleDataTypeById(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
            return;
        }
        Program program = getCurrentProgram();
        if (program == null) {
            sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
            return;
        }

        try {
            String path = exchange.getRequestURI().getPath();
            String idStr = path.substring("/datatypes/by-id/".length());
            idStr = java.net.URLDecoder.decode(idStr, "UTF-8");

            if (idStr.isEmpty()) {
                sendErrorResponse(exchange, 400, "Universal ID is required", "MISSING_PARAMETER");
                return;
            }

            UniversalID universalId;
            try {
                universalId = new UniversalID(Long.parseLong(idStr));
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, 400, "Invalid universal ID format: " + idStr, "INVALID_PARAMETER");
                return;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dtm.findDataTypeForID(universalId);

            if (dataType == null) {
                sendErrorResponse(exchange, 404, "DataType not found with ID: " + idStr, "DATATYPE_NOT_FOUND");
                return;
            }

            Map<String, Object> dataTypeInfo = buildDataTypeInfo(dataType);

            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(dataTypeInfo);

            sendJsonResponse(exchange, builder.build(), 200);

        } catch (Exception e) {
            Msg.error(this, "Error retrieving datatype by ID", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Handle POST /datatypes - Add new datatype from C-parsed string
     */
    private void handleCreateUpdateDataType(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod()) && !"PUT".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed", "METHOD_NOT_ALLOWED");
            return;
        }

        try {
            Map<String, String> params = parseJsonPostParams(exchange);

            // Debug - log all parameters received by this method
            StringBuilder debugInfo = new StringBuilder("DEBUG handleCreateDataType - Received parameters: ");
            for (Map.Entry<String, String> entry : params.entrySet()) {
                debugInfo.append(entry.getKey()).append("=").append(entry.getValue()).append(", ");
            }
            Msg.info(this, debugInfo.toString());

            String cDataTypeStr = params.get("cDataType");
            String categoryPathStr = params.get("categoryPath");

            Msg.info(this, "handleCreateDataType - extracted parameters: cDataType=" + cDataTypeStr +
                           ", categoryPath=" + categoryPathStr);

            if (cDataTypeStr == null || cDataTypeStr.trim().isEmpty()) {
                Msg.info(this, "handleCreateDataType - Missing required parameter: cDataType");
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
                        addedDataType = dtm.addDataType(parsedDataType, "POST".equals(exchange.getRequestMethod()) ? DataTypeConflictHandler.DEFAULT_HANDLER : DataTypeConflictHandler.REPLACE_HANDLER);
                    }catch (Exception e) {
                        Msg.error(this, "Error creating category path: " + categoryPath +  e);
                        return e;
                    }

                    if ("POST".equals(exchange.getRequestMethod()) || (categoryPathStr != null && !categoryPathStr.trim().isEmpty())) {
                        addedDataType.setCategoryPath(categoryPath);
                    }

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
}