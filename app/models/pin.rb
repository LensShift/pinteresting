class Pin < ActiveRecord::Base
	belongs_to :user

	has_attached_file :image, :styles => { :medium => "300x300>", :thumb =>"100x100>"}
	validates_attachment_content_type :image, :content_type => ["image/jpg", "image/jpeg", "image/png", "image/gif"]

	validates :description, presence: true
	validates :image, presence: true
end

require 'paperclip/media_type_spoof_detector'
	module Paperclip
	  class MediaTypeSpoofDetector
	    def spoofed?
	      false
	    end
	  end
	end
	# follow this with the class
	class Pin < ActiveRecord::Base
	#contents of your current model.
	end