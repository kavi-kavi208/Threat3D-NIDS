export interface ChatMessage {
  sender: 'user' | 'bot';
  text: string;
  severity?: string;
  score?: number;
  mitre?: string[];
  recommendations?: string[];
}

export interface ChatResponse {
  /**
   * Primary answer text to display in the chat.
   */
  answer: string;
  /**
   * Optional severity string (e.g., LOW, MEDIUM, HIGH, CRITICAL).
   */
  severity?: string;
  /**
   * Optional numeric score (0‑100).
   */
  score?: number;
  /**
   * Optional MITRE technique IDs.
   */
  mitre?: string[];
  /**
   * Optional list of mitigation recommendations.
   */
  recommendations?: string[];
}
