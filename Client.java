import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Client {

    public static void main(String[] args) throws IOException {

        URL url = new URL("http://localhost:8765/Mahdi");
//        URL url = new URL("http://apapi.haditabatabaei.ir/docs");

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");

        System.out.println(connection.getResponseCode());
        System.out.println(connection.getResponseMessage());

        InputStream inputStream = connection.getInputStream();
        StringBuilder response = new StringBuilder();

        int data = inputStream.read();
        while(data != -1) {
            response.append((char)data);
            data = inputStream.read();
        }
        inputStream.close();

        System.out.println(response);
    }
}