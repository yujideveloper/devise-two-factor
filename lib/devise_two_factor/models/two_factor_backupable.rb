module Devise
  module Models
    # TwoFactorBackupable allows a user to generate backup codes which
    # provide one-time access to their account in the event that they have
    # lost access to their two-factor device
    module TwoFactorBackupable
      extend ActiveSupport::Concern

      included do
        otp_backup_codes_store_association_name = otp_backup_codes_store_name || "self"
        class_eval <<-METHODS, __FILE__, __LINE__ + 1
          def otp_backup_codes_store
            #{otp_backup_codes_store_association_name}
          end
        METHODS
      end

      def self.required_fields(klass)
        [:otp_backup_codes]
      end

      # 1) Invalidates all existing backup codes
      # 2) Generates otp_number_of_backup_codes backup codes
      # 3) Stores the hashed backup codes in the database
      # 4) Returns a plaintext array of the generated backup codes
      def generate_otp_backup_codes!
        codes           = []
        number_of_codes = self.class.otp_number_of_backup_codes
        code_length     = self.class.otp_backup_code_length

        number_of_codes.times do
          codes << SecureRandom.hex(code_length)
        end

        hashed_codes = codes.map { |code| Devise::Encryptor.digest(self.class, code) }
        otp_backup_codes_store.otp_backup_codes = hashed_codes

        codes
      end

      # Returns true and invalidates the given code
      # if that code is a valid backup code.
      def invalidate_otp_backup_code!(code)
        codes = otp_backup_codes_store.otp_backup_codes || []

        codes.each do |backup_code|
          next unless Devise::Encryptor.compare(self.class, backup_code, code)

          codes.delete(backup_code)
          otp_backup_codes_store.otp_backup_codes = codes
          save!(validate: false)
          return true
        end

        false
      end

    protected

      module ClassMethods
        Devise::Models.config(self, :otp_backup_code_length,
                                    :otp_number_of_backup_codes,
                                    :otp_backup_codes_store_name,
                                    :pepper)
      end
    end
  end
end
