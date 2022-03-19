package google;

import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePart;
import google.model.MailQuery;

import java.io.IOException;
import java.util.List;

public interface GmailService {
    List<Message> waitForEmailsToBeReceivedAndReturnThem(MailQuery mailQuery, int... secondsToWait) throws IOException;
    Message getMessageById(String messageId) throws IOException;
    List<MessagePart> getMessageParts(Message message);
    String getMessageBodyHtml(MessagePart messagePart);
    void deleteMessage(String messageId) throws IOException;
}
