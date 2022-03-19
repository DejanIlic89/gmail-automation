package google;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.StringUtils;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePart;
import google.model.MailQuery;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.awaitility.core.ConditionTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;

@RequiredArgsConstructor
public class GmailServiceImpl implements GmailService {

    @NonNull
    private Gmail service = getService();

    private static final Logger LOGGER = LoggerFactory.getLogger(GmailServiceImpl.class);

    /** Application name. */
    private static final String APPLICATION_NAME = "Dejan Gmail API";
    /** Global instance of the JSON factory. */
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    /** Directory to store authorization tokens for this application. */
//    private static final String TOKENS_DIRECTORY_PATH = "src/main/resources/google";
    private static final File DATA_STORE_DIR = new File(Objects.requireNonNull(ClassLoader.getSystemClassLoader().getResource("google/")).getFile());

    /**
     * Global instance of the scopes required by this quickstart.
     * If modifying these scopes, delete your previously saved tokens/ folder.
     */
    private static final List<String> SCOPES = Collections.singletonList(GmailScopes.MAIL_GOOGLE_COM);
    private static final String CREDENTIALS_FILE_PATH = "/google/client_secret.json";

    /**
     * Global instance of the {@link DataStoreFactory}. The best practice is to make it a single
     * globally shared instance across your application.
     */
    private static FileDataStoreFactory dataStoreFactory;

    static {
        try {
            dataStoreFactory = new FileDataStoreFactory(DATA_STORE_DIR);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Global instance of the HTTP transport.
     */
    private static HttpTransport httpTransport;

    static {
        try {
            httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    /**
     * Creates an authorized Credential object.
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        InputStream in = GmailServiceImpl.class.getResourceAsStream(CREDENTIALS_FILE_PATH);
        if (in == null) {
            throw new FileNotFoundException("Resource not found: " + CREDENTIALS_FILE_PATH);
        }
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(dataStoreFactory)
//                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
        //returns an authorized Credential object.
        return credential;
    }

    /**
     * Create a MimeMessage using the parameters provided.
     *
     * @param to email address of the receiver
     * @param from email address of the sender, the mailbox account
     * @param subject subject of the email
     * @param bodyText body text of the email
     * @return the MimeMessage to be used to send email
     * @throws MessagingException
     */
    public static MimeMessage createEmail(String to,
                                          String from,
                                          String subject,
                                          String bodyText)
            throws MessagingException {
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage email = new MimeMessage(session);

        email.setFrom(new InternetAddress(from));
        email.addRecipient(javax.mail.Message.RecipientType.TO, new InternetAddress(to));
        email.setSubject(subject);
        email.setText(bodyText);
        return email;
    }

    /**
     * Create a message from an email.
     *
     * @param emailContent Email to be set to raw of message
     * @return a message containing a base64url encoded email
     * @throws IOException
     * @throws MessagingException
     */
    public static Message createMessageWithEmail(MimeMessage emailContent)
            throws MessagingException, IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        emailContent.writeTo(buffer);
        byte[] bytes = buffer.toByteArray();
        String encodedEmail = Base64.encodeBase64URLSafeString(bytes);
        Message message = new Message();
        message.setRaw(encodedEmail);
        return message;
    }

    /**
     * Send an email from the user's mailbox to its recipient.
     *
     * @param service Authorized Gmail API instance.
     * @param userId User's email address. The special value "me"
     * can be used to indicate the authenticated user.
     * @param emailContent Email to be sent.
     * @return The sent message
     * @throws MessagingException
     * @throws IOException
     */
    public static Message sendMessage(Gmail service,
                                      String userId,
                                      MimeMessage emailContent)
            throws MessagingException, IOException {
        Message message = createMessageWithEmail(emailContent);
        message = service.users().messages().send(userId, message).execute();

        System.out.println("Message id: " + message.getId());
        System.out.println(message.toPrettyString());
        return message;
    }

    private Gmail getService() {
        Credential credential = authorize();
        service = new Gmail.Builder(httpTransport, JSON_FACTORY, credential)
                .setApplicationName(APPLICATION_NAME)
                .build();
        return service;
    }

    private Credential authorize() {
        Credential credential = null;
        try (InputStream inputStream = Objects.requireNonNull(ClassLoader.getSystemClassLoader().getResource("google/client_secret.json")).openStream()) {
            GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(inputStream));
            //Build flow and trigger user authorization request.
            GoogleAuthorizationCodeFlow flow =
                    new GoogleAuthorizationCodeFlow.Builder(
                            httpTransport, JSON_FACTORY, clientSecrets, SCOPES)
                            .setDataStoreFactory(dataStoreFactory)
                            .setAccessType("offline")
                            .build();
            credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize("user");
        } catch (IOException ioex) {
            LOGGER.error(ioex.getMessage());
        }
        return credential;
    }

    public static void main(String... args) throws IOException, GeneralSecurityException, MessagingException {
        final MailQuery mailQuery = new MailQuery();
        GmailServiceImpl serv = new GmailServiceImpl();
        // Build a new authorized API client service.
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();

        // Print the labels in the user's account.
        String user = "me";

        //list labels
//        ListLabelsResponse listResponse = service.users().labels().list(user).execute();
//        List<Label> labels = listResponse.getLabels();
//        if (labels.isEmpty()) {
//            System.out.println("No labels found.");
//        } else {
//            System.out.println("Labels:");
//            for (Label label : labels) {
//                System.out.printf("- %s\n", label.getName());
//            }
//        }

        //send message
//        MimeMessage mimeMessage = createEmail("dejan.ilic.test@gmail.com",
//                "draganadejan69@gmail.com", "sender: dejan.ilic.test@gmail.com | receiver: draganadejan69@gmail.com | 2022", "Dragana I love you");
//        sendMessage(service, user, mimeMessage);


        //get message by subject
        mailQuery.setSubject("sender: dejan.ilic.test@gmail.com");
        List<Message> messages = serv.waitForEmailsToBeReceivedAndReturnThem(mailQuery);
        Message messageById = serv.getMessageById(messages.get(0).getId());
        String messageBodyAsHtml = StringUtils.newStringUtf8(Base64.decodeBase64(messageById.getPayload().getBody().getData()));
        System.out.println(messageBodyAsHtml);
    }

    /**
     * Get list of messages queried by parameters for set amount of seconds as maximum, 180 by default
     * @param mailQuery
     * @param secondsToWait
     * @return
     * @throws IOException
     */
    @Override
    public List<Message> waitForEmailsToBeReceivedAndReturnThem(MailQuery mailQuery, int... secondsToWait) throws IOException {
        final int timeout = secondsToWait.length > 0 ? secondsToWait[0] : 180;
        try {
            await()
                    .atMost(timeout, TimeUnit.SECONDS)
                    .pollInterval(5, TimeUnit.SECONDS)
                    .until(() -> listMessagesByQuery(mailQuery) != null);
        } catch (ConditionTimeoutException e) {
            throw new ConditionTimeoutException("Email was not received within " + timeout + " seconds for receiver " + mailQuery.getReceiver());
        }
        return listMessagesByQuery(mailQuery);
    }

    /**
     * get list of messages queried by parameters
     * @param mailQuery
     * @return
     * @throws IOException
     */
    private List<Message> listMessagesByQuery(MailQuery mailQuery) throws IOException {
        final String query = createQuery(mailQuery);
        return service.users().messages()
                .list("me")
                .setQ(query)
                .execute()
                .getMessages();
    }

    /**
     * Create query string based on passed parameters
     * @param mailQuery
     * @return
     */
    private String createQuery(MailQuery mailQuery) {
        final String label = mailQuery.getLabel() != null ? "label:" + mailQuery.getLabel() : "";
        final String subject = mailQuery.getSubject() != null ? "subject:" + mailQuery.getSubject() : "";
        final String sender = mailQuery.getSender() != null ? "from:" + mailQuery.getSender() : "";
        final String receiver = mailQuery.getReceiver() != null ? "to:" + mailQuery.getReceiver() : "";

        StringBuilder query = new StringBuilder();
        if (!label.isEmpty()) query.append(label).append(" ");
        if (!subject.isEmpty()) query.append(subject).append(" ");
        if (!sender.isEmpty()) query.append(sender).append(" ");
        if (!receiver.isEmpty()) query.append(receiver).append(" ");
        return String.valueOf(query);
    }

    /**
     * Get message content by message ID.
     * @param messageId
     * @return message
     * @throws IOException
     */
    @Override
    public Message getMessageById(String messageId) throws IOException {
        return service.users().messages()
                .get("me", messageId)
                .execute();
    }

    /**
     * Get message parts for extracting body
     * @param message
     * @return list of message parts
     */
    @Override
    public List<MessagePart> getMessageParts(Message message) {
        return message.getPayload().getParts();
    }

    /**
     * Convert message body as HTML string.
     * @param messagePart
     * @return message body as HTML
     */
    @Override
    public String getMessageBodyHtml(MessagePart messagePart) {
        return StringUtils.newStringUtf8(Base64.decodeBase64(messagePart.getBody().getData()));
    }

    /**
     * Delete message by message ID.
     * @param messageId
     * @throws IOException
     */
    @Override
    public void deleteMessage(String messageId) throws IOException {
        service.users().messages()
                .delete("me", messageId)
                .execute();
    }
}