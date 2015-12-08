from pydiesel.reflection import ReflectionException
from drozer.modules import Module, common
from drozer.modules.common.package_manager import PackageManager
from drozer import android
import os, sys

class Detect(Module, common.Filters, common.PackageManager, common.Provider, common.Strings, common.FileSystem, common.ZipFile):
    name = "Detect Provider Security Hole"
    description = "Detect the providers, find the security holes"
    examples = "run apksec.provider.detect"
    date = "2015-10-14"
    author = "Xiaofang Huang"
    license = "MWR Code License"
    path = ["apksec","provider"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", default = None, help = "specify the package to inspect")

    def execute(self, arguments):
        self.stdout.write("Successfully relize a new module named 'apksec.provider.detect'!\n")

        reload(sys)
        sys.setdefaultencoding('utf-8')

        if arguments.package != None:
            count = 1
            self.stdout.write("provider uri detecting starts...\n")

            for uri in self.findAllContentUris(arguments.package):
                self.stdout.write("  No.%d: %s\n" % (count, uri))
                count = count + 1

                try:
                    cursor = self.contentResolver().query(uri)
                except ReflectionException as e:
                    self.stdout.write("    Could not query from URI %s \n" % uri)
                    continue

                if cursor != None:
                    self.stdout.write("    Accessible Tables From URI: %s \n" % uri)
                    if(str(uri).startswith("content://media/internal/audio/")):
                        pass
                    
                    """
                    CRUD Detection added by hxf 20151127
                    """
                    self.update_record(cursor, uri)
                    
                    cursor = self.contentResolver().query(uri)
                    self.insert_record(cursor, uri)
                else:
                    self.stdout.write("    Accesible but Query Result is None!!!\n")
                    
        else:
            self.stdout.write("packagename could not be None!\n ")


    def findAllContentUris(self, package):
        uris = set([])

        if package == None:
            for package in self.packageManager().getPackages(PackageManager.GET_PROVIDERS | PackageManager.GET_URI_PERMISSION_PATTERNS):
                try:
                    uris = uris.union(self.__search_package(package))
                except ReflectionException as e:
                    if "java.util.zip.ZipException: unknown format" in e.message:
                        self.stderr.write("Skipping package %s, because we cannot unzip it..." % package.applicationInfo.packageName)
                    else:
                        raise
        else:
            package = self.packageManager().getPackageInfo(package, PackageManager.GET_PROVIDERS)
            try:
                uris = uris.union(self.__search_package(package))
                uid = package.applicationInfo.uid
            except ReflectionException as e:
                if "java.util.zip.ZipException: unknown format" in e.message:
                    self.stderr.write("Skipping package %s, because we cannot unzip it..." % package.applicationInfo.packageName)
                else:
                    raise

        return uris


    def __search_package(self, package):
        uris = set([])

        if package.providers != None:
            for provider in package.providers:
                if provider.authority != None:
                    paths = set([])

                    if provider.uriPermissionPatterns != None:
                        for pattern in provider.uriPermissionPatterns:
                            paths.add(pattern.getPath())
                    if provider.pathPermissions != None:
                        for permission in provider.pathPermissions:
                            paths.add(permission.getPath())

                    for authority in provider.authority.split(";"):
                        uris.add("content://%s/" % authority)
                        for path in paths:
                            uris.add("content://%s%s" % (authority, path))

        for (path, content_uris) in self.findContentUris(package.packageName):
            if len(content_uris) > 0:
                for uri in content_uris:
                    uris.add(uri[uri.upper().find("CONTENT"):])

        for uri in set(uris):
            if uri.endswith("/"):
                uris.add(uri[uri.upper().find("CONTENT"):-1])
            else:
                uris.add(uri[uri.upper().find("CONTENT"):] + "/")

        return sorted(uris)


    def insert_record(self, cursor, uri):
        data_int = 13991625
        data_float = 526.00856
        data_string = "Data__DrozerTest_llf"
        
        self.stdout.write("    Inserting data...\n")
    
        values = self.new("android.content.ContentValues")
    
        type_blob = self.klass("android.database.Cursor").FIELD_TYPE_BLOB
        type_int = self.klass("android.database.Cursor").FIELD_TYPE_INTEGER
        type_float = self.klass("android.database.Cursor").FIELD_TYPE_FLOAT
        type_none = self.klass("android.database.Cursor").FIELD_TYPE_NULL
        type_string = self.klass("android.database.Cursor").FIELD_TYPE_STRING
    
        if cursor != None:
            columns = cursor.getColumnNames() 
            cursor.moveToFirst()
            
            if cursor.isAfterLast() == False:
                for i in xrange(1, len(columns)):
                    try:
                        if cursor.getType(i) == type_int:
                            values.put(str(columns[i]), data_int)
                        else:
                            if cursor.getType(i) == type_float:
                                values.put(str(columns[i]), data_float)
                            else:
                                values.put(str(columns[i]), data_string)
                                        
                    except ReflectionException as e:
                        self.stdout.write("    Insert data Error:" + e.message + "\n\n")
                        raise
                    
        try:
            insert = self.contentResolver().insert(uri, values)
            if(str(insert) != "null"):
                self.stdout.write("    Inserted successfully!!!\n")
                rows = self.getResultSet(self.contentResolver().query(uri))
                self.file_table(rows)   
            else:
                self.stdout.write("    Inserted Failed!!!\n")       
        except ReflectionException as e:
            self.stdout.write("    Insert data Error:" + e.message + "\n\n")
            return
        
        """
        Delete Detection
        """
        cursor = self.contentResolver().query(uri)
        self.delete_record(cursor, uri)
        
        rows = self.getResultSet(self.contentResolver().query(uri))
        self.file_table(rows)
        
        
    def update_record(self, cursor, uri):
        """
        update the first record. that is the index of 'rows' is 1
        """
        rows = self.getResultSet(cursor)
        row1_original = rows[1]
            
        #row_to_update = []
        data_int = 13991625
        data_float = 526.00856
        data_string = "Data__DrozerTest_llf"
        
        self.stdout.write("    Updating the first record...\n")
        
        values_to_update = self.new("android.content.ContentValues")
        values_row1_original = self.new("android.content.ContentValues")
        
        type_blob = self.klass("android.database.Cursor").FIELD_TYPE_BLOB
        type_int = self.klass("android.database.Cursor").FIELD_TYPE_INTEGER
        type_float = self.klass("android.database.Cursor").FIELD_TYPE_FLOAT
        type_none = self.klass("android.database.Cursor").FIELD_TYPE_NULL
        type_string = self.klass("android.database.Cursor").FIELD_TYPE_STRING
        
        if cursor != None:
            columns = cursor.getColumnNames()
            cursor.moveToFirst()
            for i in xrange(1, len(columns)):
                
                try:     
                    if cursor.getType(i) == type_int:
                        values_to_update.put(str(columns[i]), data_int)
                    else:
                        if cursor.getType(i) == type_float:
                            values_to_update.put(str(columns[i]), data_float)
                        else:
                            values_to_update.put(str(columns[i]), data_string)
                                    
                except ReflectionException as e:
                    self.stdout.write("    Update Error:" + e.message + "\n\n")
                    
            try:
                """
                update the first record row1!
                """
                update = self.contentResolver().update(uri, values_to_update, columns[0] + "=?", str(row1_original[0]).split("\n"))
                if update > 0:
                    self.stdout.write("    Update successfully!!!\n")
                    rows = self.getResultSet(self.contentResolver().query(uri))
                    self.file_table(rows)
                
                """
                update the row1 back to original state! 
                assign the row1_original to values_row1_original
                """    
                self.stdout.write("    Updating the first record back to the original state!!!\n")
                
                for j in xrange(1, len(columns)):
                    values_row1_original.put(str(columns[j]), row1_original[j])
                    
                update = self.contentResolver().update(uri, values_row1_original, columns[0] + "=?", str(row1_original[0]).split("\n"))
                if update > 0:
                    self.stdout.write("    Update successfully!!!\n")
                    rows = self.getResultSet(self.contentResolver().query(uri))
                    self.file_table(rows)
                
            except ReflectionException as e:
                self.stdout.write("    Update Error:" + e.message + "\n\n")
    
    
    def delete_record(self, cursor, uri):
        data_int = 13991625
        data_float = 526.00856
        data_string = "Data__DrozerTest_llf"
        
        self.stdout.write("    Deleting data...\n")
        delete = "delete"
        
        type_blob = self.klass("android.database.Cursor").FIELD_TYPE_BLOB
        type_int = self.klass("android.database.Cursor").FIELD_TYPE_INTEGER
        type_float = self.klass("android.database.Cursor").FIELD_TYPE_FLOAT
        type_none = self.klass("android.database.Cursor").FIELD_TYPE_NULL
        type_string = self.klass("android.database.Cursor").FIELD_TYPE_STRING
        
        where = ""
        where_args = []
        
        if cursor != None:
            columns = cursor.getColumnNames()
            cursor.moveToFirst()
            if cursor.isAfterLast() == False:
                try:
                    for i in xrange(1, len(columns)):
                        where = where + str(columns[i]) + "=?"
                        if cursor.getType(i) == type_int:
                            where_args.append(data_int)
                        else:
                            if cursor.getType(i) == type_float:
                                where_args.append(data_float)
                            else:
                                where_args.append(data_string)
                                
                        if i != len(columns)-1:
                            where = where + " and "
                                
                    delete = self.contentResolver().delete(uri, where, where_args)
                except ReflectionException as e:
                    self.stdout.write("    Delete Error:" + e.message + "\n")
                    raise
                    return
                
        if str(delete) != "delete":
            self.stdout.write("    Deleted successfully!!!\n")
        else:
            self.stdout.write("    Noting can be deleted!!!\n")
            
            
                          
    def getResultSet(self, cursor):
        """
        Get a result set from a database cursor, as a 2D array.
        """

        rows = []
        blob_type = self.klass("android.database.Cursor").FIELD_TYPE_BLOB
        int_type= self.klass("android.database.Cursor").FIELD_TYPE_INTEGER
        float_type=self.klass("android.database.Cursor").FIELD_TYPE_FLOAT
        if cursor != None:
            columns = cursor.getColumnNames()
            
            rows.append(columns)
            #self.stdout.write("Record counts:"+''.join(len(columns)))
            cursor.moveToFirst()
            while cursor.isAfterLast() == False:
                row = []

                for i in xrange(len(columns)):
                    try:
                        if(cursor.getType(i) == blob_type):
                            row.append("%s (Base64-encoded)" % (cursor.getBlob(i).base64_encode()))
                                    
                        else:
                            if(cursor.getType(i)==int_type):
                                row.append(str(cursor.getInt(i)))
                            else:
                                if(cursor.getType(i)==float_type):
                                    row.append(str(cursor.getFloat(i)))
                                else:   
                                    row.append(cursor.getString(i))
                                    
                    except ReflectionException as e:
                        if e.message.startswith("getType"):
                            try:
                                row.append(cursor.getString(i))
                            except ReflectionException as e:
                                if e.message.startswith("unknown error: Unable to convert BLOB to string"):
                                    row.append("%s (Base64-encoded)" % (cursor.getBlob(i).base64_encode()))
                                else:
                                    raise
                        else:
                            raise

                rows.append(row)

                cursor.moveToNext()

            return rows
        else:
            return None
    
    
    def file_table(self, rows, show_headers=True, vertical=False):
        """
        Print tabular data to files, given an array of rows, each containing
        an array of values.

        It is assumed that the first row contains column headers.
        """

        if vertical:
            self.file_table_vertical(rows)
        else:
            self.file_table_horizontal(rows, show_headers)
              
        
    def file_table_horizontal(self, rows, show_headers=True):
        """
        Print tabular data in a traditional, horizontal format:
        | a | b | c |
        | 1 | 2 | 3 |
        """
        widths = []

        if show_headers:
            self.stdout.write("    |")

        for i in xrange(len(rows[0])):
            widths.append(max(map(lambda r: len(str(r[i])), rows)))

            if show_headers:
                self.stdout.write((" {:<" + str(widths[i]) + "} |").format(rows[0][i]))
        self.stdout.write("\n")

        for r in rows[1:]:
            self.stdout.write("    |")
            for i in xrange(len(r)):
                self.stdout.write((" {:<" + str(widths[i]) + "} |").format(r[i]))
            self.stdout.write("\n")
        self.stdout.write("\n")
        
        
    def file_table_vertical(self, rows):
        """
        Print tabular data in a vertical format, which is easier to read with
        long fields names or values:

        a: 1
        b: 2
        c: 3
        """
        headers = rows.pop(0)

        width = max(map(lambda e: len(str(e)), headers))

        for row in rows:
            self.stdout.write("    ")
            for i in xrange(len(headers)):
                self.stdout.write(("{:>" + str(width) + "}  {}\n").format(headers[i], row[i]))
            self.stdout.write("\n")
        self.stdout.write("\n")
